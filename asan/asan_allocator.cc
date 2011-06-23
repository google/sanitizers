/* Copyright 2011 Google Inc.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

// This file is a part of AddressSanitizer, an address sanity checker.
// *************
//  NOTE: this file is not used by the rtl yet
// *************

#include "asan_allocator.h"
#include "asan_int.h"
#include "asan_mapping.h"
#include "asan_rtl.h"
#include "asan_stats.h"
#include "asan_thread.h"

#include <sys/mman.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <algorithm>

void *(*__asan_real_malloc)(size_t);
void (*__asan_real_free)(void *ptr);

namespace {

static const size_t kRedzone      = kMinRedzone * 2;
static const size_t kMinAllocSize = kRedzone * 2;
static const size_t kMinMmapSize  = kPageSize * 128;
static const uint64_t kMaxAllowedMalloc =
    __WORDSIZE == 32 ? 0x7fffffffULL : (1ULL << 40);


static void ShowStatsAndAbort() {
  __asan_stats.PrintStats();
  abort();
}

static void OutOfMemoryMessage(const char *mem_type, size_t size) {
  Printf("==%d== ERROR: AddressSanitizer failed to allocate "
         "0x%lx (%ld) bytes of %s\n",
         getpid(), size, size, mem_type);
}

static inline bool IsAligned(uintptr_t a, uintptr_t alignment) {
  return (a & (alignment - 1)) == 0;
}

static inline bool IsWordAligned(uintptr_t a) {
  return IsAligned(a, kWordSize);
}

static inline bool IsPowerOfTwo(size_t x) {
  return (x & (x - 1)) == 0;
}

static inline size_t Log2(size_t x) {
  CHECK(IsPowerOfTwo(x));
  return __builtin_ctzl(x);
}

static inline size_t RoundUpTo(size_t size, size_t boundary) {
  CHECK(IsPowerOfTwo(boundary));
  return (size + boundary - 1) & ~(boundary - 1);
}

static inline size_t RoundUpToPowerOfTwo(size_t size) {
  CHECK(size);
  if (IsPowerOfTwo(size)) return size;
  size_t up = __WORDSIZE - __builtin_clzl(size);
  CHECK(size < (1ULL << up));
  CHECK(size > (1ULL << (up - 1)));
  return 1UL << up;
}

static void PoisonShadow(uintptr_t mem, size_t size, uint8_t poison) {
  CHECK(IsAligned(mem,        kShadowGranularity));
  CHECK(IsAligned(mem + size, kShadowGranularity));
  uintptr_t shadow_beg = MemToShadow(mem);
  uintptr_t shadow_end = MemToShadow(mem + size);
  memset((void*)shadow_beg, poison, shadow_end - shadow_beg);
}

// Given kRedzone bytes, we need to mark first size bytes
// as addressable and the rest kRedzone-size bytes as unaddressable.
static void PoisonPartialRightRedzone(uintptr_t mem, size_t size) {
  CHECK(size <= kRedzone);
  CHECK(IsAligned(mem, kRedzone));
  CHECK(IsPowerOfTwo(kShadowGranularity));
  CHECK(IsPowerOfTwo(kRedzone));
  CHECK(kRedzone >= kShadowGranularity);
  uint8_t *shadow = (uint8_t*)MemToShadow(mem);
  for (size_t i = 0; i < kRedzone; i+= kShadowGranularity, shadow++) {
    if (i + kShadowGranularity <= size) {
      *shadow = 0;  // fully addressable
    } else if (i >= size) {
      *shadow = 0xff;  // fully unaddressable
    } else {
      size_t n_addressable_bytes = size - i;
      *shadow = n_addressable_bytes;
    }
  }
}

static uint8_t *MmapNewPagesAndPoisonShadow(size_t size) {
  CHECK((size % kPageSize) == 0);
  uint8_t *res = (uint8_t*)mmap(0, size,
                   PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANON, -1, 0);
  if (res == (uint8_t*)-1) {
    OutOfMemoryMessage("main memory", size);
    abort();
  }
  PoisonShadow((uintptr_t)res, size, -1);
  return res;
}

// Every chunk of memory allocated by this allocator can be in one of 3 states:
// CHUNK_AVAILABLE: the chunk is in the free list and ready to be allocated.
// CHUNK_ALLOCATED: the chunk is allocated and not yet freed.
// CHUNK_QUARANTINE: the chunk was freed and put into quarantine zone.
//
// The pseudo state CHUNK_MEMALIGN is used to mark that the address is not 
// the beginning of a Chunk (in which case the next work contains the address
// of the Chunk).
//
// The magic numbers for the enum values are taken randomly.
enum {
  CHUNK_AVAILABLE  = 0x573B5CE5,
  CHUNK_ALLOCATED  = 0x32041A36,
  CHUNK_QUARANTINE = 0x1978BAE3,
  CHUNK_MEMALIGN   = 0xDC68ECD8,
};

struct Chunk;

struct ChunkBase {
  uintptr_t    chunk_state;     // Should be the first field.
  size_t       allocated_size;  // Must be power of two
  uintptr_t    beg;
  size_t       used_size;
  Chunk       *next;
  Chunk       *prev;
  AsanThread  *alloc_thread;
  AsanThread  *free_thread;
};

struct Chunk: public ChunkBase {
  uintptr_t alloc_stack[(kRedzone - sizeof(ChunkBase)) / kWordSize];
  uintptr_t free_stack[kRedzone / kWordSize];

  bool AddrIsInside(uintptr_t addr, size_t access_size, size_t *offset) {
    if (addr >= beg && (addr + access_size) <= (beg + used_size)) {
      *offset = addr - beg;
      return true;
    }
    return false;
  }

  bool AddrIsAtLeft(uintptr_t addr, size_t access_size, size_t *offset) {
    if (addr >= (uintptr_t)this && addr < beg) {
      *offset = beg - addr;
      return true;
    }
    return false;
  }

  bool AddrIsAtRight(uintptr_t addr, size_t access_size, size_t *offset) {
    if (addr + access_size >= beg + used_size &&
        addr < (uintptr_t)this + allocated_size + kRedzone) {
      if (addr <= beg + used_size)
        *offset = 0;
      else
        *offset = addr - (beg + used_size);
      return true;
    }
    return false;
  }

  void DescribeAddress(uintptr_t addr, size_t access_size) {
    size_t offset;
    Printf(""PP" is located ", addr);
    if (AddrIsInside(addr, access_size, &offset)) {
      Printf("%ld bytes inside of", offset);
    } else if (AddrIsAtLeft(addr, access_size, &offset)) {
      Printf("%ld bytes to the left of", offset);
    } else if (AddrIsAtRight(addr, access_size, &offset)) {
      Printf("%ld bytes to the right of", offset);
    } else {
      Printf(" somewhere around (this is AddressSanitizer bug!)");
    }
    Printf(" %ld-byte region ["PP","PP")\n" , used_size, beg, beg + used_size);
  }
};

class MallocInfo {
 public:
  Chunk *AllocateChunk(size_t size) {
    ScopedLock lock(&mu_);

    CHECK(IsPowerOfTwo(size));

    size_t idx = Log2(size);
    if (!chunks[idx]) {
      GetNewChunks(size);
    }
    Chunk *m = chunks[idx];
    CHECK(m);
    chunks[idx] = m->next;
    m->next = m->prev = 0;
    CHECK(m->chunk_state == CHUNK_AVAILABLE);
    m->chunk_state = CHUNK_ALLOCATED;

    if (malloced_items_) {
      malloced_items_->prev = m;
    }
    m->next = malloced_items_;
    malloced_items_ = m;
    return m;
  }

  void DeallocateChunk(Chunk *m) {
    ScopedLock lock(&mu_);

    CHECK(m);
    CHECK(m->chunk_state == CHUNK_ALLOCATED);
    CHECK(IsPowerOfTwo(m->allocated_size));
    CHECK(__asan_flag_quarantine_size > 0);

    // remove from malloced list.
    {
      if (m == malloced_items_) {
        malloced_items_ = m->next;
        if (malloced_items_)
          malloced_items_->prev = 0;
      } else {
        Chunk *prev = m->prev;
        Chunk *next = m->next;
        if (prev) prev->next = next;
        if (next) next->prev = prev;
      }
    }

    if (!quarantine_) {
      m->next = m->prev = m;
    } else {
      Chunk *prev = quarantine_->prev;
      Chunk *next = quarantine_;
      m->next = next;
      m->prev = prev;
      prev->next = m;
      next->prev = m;
    }
    quarantine_ = m;
    quarantine_size_ += m->allocated_size;
    m->chunk_state = CHUNK_QUARANTINE;
    while (quarantine_size_ &&
           (quarantine_size_ > __asan_flag_quarantine_size)) {
      Pop();
    }

  }

  Chunk *FindMallocedOrFreed(uintptr_t addr, size_t access_size) {
    ScopedLock lock(&mu_);

    Chunk *i = quarantine_;
    if (!i) return NULL;
    size_t offset;
    size_t best_offset = -1;
    Chunk *best_match = NULL;
    // search in the freed chunks.
    do {
      if (i->AddrIsInside(addr, access_size, &offset)) {
        return i; // found exact match
      }
      if (i->AddrIsAtLeft(addr, access_size, &offset) ||
          i->AddrIsAtRight(addr, access_size, &offset)) {
        if (offset < best_offset) {
          best_match = i;
          best_offset = offset;
        }
      }
      i = i->next;
    } while (i != quarantine_);

    // search in the malloced chunks.
    for (i = malloced_items_; i; i = i->next) {
      if (i->AddrIsInside(addr, access_size, &offset)) {
        return i; // found exact match
      }
      if (i->AddrIsAtLeft(addr, access_size, &offset) ||
          i->AddrIsAtRight(addr, access_size, &offset)) {
        if (offset < best_offset) {
          best_match = i;
          best_offset = offset;
        }
      }
    }
    return best_match;
  }

 private:
  void Pop() {
    CHECK(quarantine_);
    CHECK(quarantine_size_ > 0);
    Chunk *m = quarantine_->prev;
    CHECK(m);
    // Printf("pop  : %p quarantine_size_ = %ld; size = %ld\n", m, quarantine_size_, m->size);
    Chunk *next = m->next;
    Chunk *prev = m->prev;
    CHECK(next && prev);
    if (next == m) {
      quarantine_ = NULL;
    } else {
      next->prev = prev;
      prev->next = next;
    }
    CHECK(quarantine_size_ >= m->allocated_size);
    quarantine_size_ -= m->allocated_size;
    // if (F_v >= 2) Printf("MallocInfo::pop %p\n", m);

    CHECK(m->chunk_state == CHUNK_QUARANTINE);
    m->chunk_state = CHUNK_AVAILABLE;
    size_t idx = Log2(m->allocated_size);
    m->next = chunks[idx];
    chunks[idx] = m;
  }

  void GetNewChunks(size_t size) {
    size_t idx = Log2(size);
    CHECK(chunks[idx] == NULL);
    CHECK(IsPowerOfTwo(size));
    CHECK(IsPowerOfTwo(kMinMmapSize));
    size_t mmap_size = std::max(size, kMinMmapSize);
    size_t n_chunks = mmap_size / size;
    if (size < kPageSize) {
      // Size is small, just poison the last chunk.
      n_chunks--;
    } else {
      // Size is large, allocate an extra page at right and poison it.
      mmap_size += kPageSize;
    }
    CHECK(n_chunks > 0);
    uint8_t *mem = MmapNewPagesAndPoisonShadow(mmap_size);
    for (size_t i = 0; i < n_chunks; i++) {
      Chunk *m = (Chunk*)(mem + i * size);
      m->chunk_state = CHUNK_AVAILABLE;
      m->allocated_size = size;
      m->next = chunks[idx];
      chunks[idx] = m;
    }
    PageGroup *pg = (PageGroup*)(mem + n_chunks * size);
    // This memory is already poisoned, no need to poison it again.
    pg->beg = (uintptr_t)mem;
    pg->end = pg->beg + mmap_size;
    pg->next = page_groups_;
    page_groups_ = pg;
  }


  Chunk *chunks[__WORDSIZE];
  Chunk *quarantine_;
  size_t quarantine_size_;
  Chunk *malloced_items_;
  AsanLock mu_;

  // All pages we ever allocated.
  struct PageGroup {
    uintptr_t beg;
    uintptr_t end;
    PageGroup *next;
  };
  PageGroup *page_groups_;
};

static MallocInfo malloc_info;

static void Describe(uintptr_t addr, size_t access_size) {
  Chunk *m = malloc_info.FindMallocedOrFreed(addr, access_size);
  if (!m) return;
  m->DescribeAddress(addr, access_size);
  CHECK(m->alloc_thread);
  if (m->free_thread) {
    Printf("freed by thread T%d here:\n", m->free_thread->tid());
    AsanStackTrace::PrintStack(m->free_stack, ASAN_ARRAY_SIZE(m->free_stack));
    Printf("previously allocated by thread T%d here:\n",
           m->alloc_thread->tid());
    AsanStackTrace::PrintStack(m->alloc_stack, ASAN_ARRAY_SIZE(m->alloc_stack));
    AsanThread::GetCurrent()->Announce();
    m->free_thread->Announce();
    m->alloc_thread->Announce();
  } else {
    Printf("allocated by thread T%d here:\n", m->alloc_thread->tid());
    AsanStackTrace::PrintStack(m->alloc_stack, ASAN_ARRAY_SIZE(m->alloc_stack));
    AsanThread::GetCurrent()->Announce();
    m->alloc_thread->Announce();
  }
}

static uint8_t *Allocate(size_t alignment, size_t size, AsanStackTrace *stack) {
  // Printf("Allocate align: %ld size: %ld\n", alignment, size);
  if (size == 0) {
    size = 1;  // TODO(kcc): do something smarter
  }
  CHECK(IsPowerOfTwo(alignment));
  size_t rounded_size = RoundUpTo(size, kRedzone);
  size_t needed_size = rounded_size + kRedzone;
  if (alignment > kRedzone) {
    needed_size += alignment;
  }
  CHECK((needed_size % kRedzone) == 0);
  if (needed_size > kMaxAllowedMalloc) {
    OutOfMemoryMessage("main memory", size);
    abort();
  }
  size_t size_to_allocate = RoundUpToPowerOfTwo(needed_size);
  CHECK(size_to_allocate >= kMinAllocSize);
  CHECK((size_to_allocate % kRedzone) == 0);

  Chunk *m = malloc_info.AllocateChunk(size_to_allocate);
  CHECK(m);
  CHECK(m->allocated_size == size_to_allocate);
  CHECK(m->chunk_state == CHUNK_ALLOCATED);
  uintptr_t addr = (uintptr_t)m + kRedzone;
  CHECK(addr == (uintptr_t)m->free_stack);

  if (alignment > kRedzone && (addr & (alignment - 1))) {
    addr = RoundUpTo(addr, alignment);
    CHECK((addr & (alignment - 1)) == 0);
    uintptr_t *p = (uintptr_t*)(addr - kRedzone);
    p[0] = CHUNK_MEMALIGN;
    p[1] = (uintptr_t)m;
  }
  m->used_size = size;
  m->beg = addr;
  m->alloc_thread = AsanThread::GetCurrent()->Ref();
  m->free_thread   = NULL;
  stack->CopyTo(m->alloc_stack, ASAN_ARRAY_SIZE(m->alloc_stack));
  PoisonShadow(addr, rounded_size, 0);
  if (size < rounded_size) {
    PoisonPartialRightRedzone(addr + rounded_size - kRedzone, size % kRedzone);
  }
  return (uint8_t*)addr;
}
__attribute__((noinline))
static void asan_clear_mem(uintptr_t *mem, size_t n_words) {
  CHECK(IsWordAligned((uintptr_t)mem));
  for (size_t i = 0; i < n_words; i++)
    mem[i] = 0;
}

__attribute__((noinline))
static void asan_copy_mem(uintptr_t *dst, uintptr_t *src, size_t n_words) {
  CHECK(IsWordAligned((uintptr_t)dst));
  CHECK(IsWordAligned((uintptr_t)src));
  for (size_t i = 0; i < n_words; i++) {
    dst[i] = src[i];
  }
}

static Chunk *PtrToChunk(uint8_t *ptr) {
  Chunk *m = (Chunk*)(ptr - kRedzone);
  if (m->chunk_state == CHUNK_MEMALIGN) {
    m = (Chunk*)((uintptr_t*)m)[1];
  }
  return m;
}

static void Deallocate(uint8_t *ptr, AsanStackTrace *stack) {
  if (!ptr) return;
  //Printf("Deallocate "PP"\n", ptr);
  Chunk *m = PtrToChunk(ptr);
  if (m->chunk_state == CHUNK_QUARANTINE) {
    Printf("attempting double-free on %p:\n", ptr);
    stack->PrintStack();
    m->DescribeAddress((uintptr_t)ptr, 1);
    ShowStatsAndAbort();
  } else if (m->chunk_state != CHUNK_ALLOCATED) {
    Printf("attempting free on address which was not malloc()-ed: %p\n", ptr);
    stack->PrintStack();
    m->DescribeAddress((uintptr_t)ptr, 1);
    ShowStatsAndAbort();
  }
  CHECK(m->chunk_state == CHUNK_ALLOCATED);
  CHECK(m->free_thread == NULL);
  CHECK(m->alloc_thread != NULL);
  m->free_thread = AsanThread::GetCurrent()->Ref();
  stack->CopyTo(m->free_stack, ASAN_ARRAY_SIZE(m->free_stack));
  size_t rounded_size = RoundUpTo(m->used_size, kRedzone);
  PoisonShadow((uintptr_t)ptr, rounded_size, -1);
  malloc_info.DeallocateChunk(m);
}

static uint8_t *Reallocate(uint8_t *old_ptr, size_t new_size, AsanStackTrace *stack) {
  if (!old_ptr) {
    return Allocate(0, new_size, stack);
  }
  if (new_size == 0) {
    return NULL;
  }
  Chunk *m = PtrToChunk(old_ptr);
  CHECK(m->chunk_state == CHUNK_ALLOCATED);
  size_t old_size = m->used_size;
  size_t memcpy_size = std::min(new_size, old_size);
  uint8_t *new_ptr = Allocate(0, new_size, stack);
  memcpy(new_ptr, old_ptr, memcpy_size);
//  asan_copy_mem((uintptr_t*)new_ptr, (uintptr_t*)old_ptr,
//                (memcpy_size + kWordSize - 1) / kWordSize);
  Deallocate(old_ptr, stack);
  __asan_stats.reallocs++;
  __asan_stats.realloced += memcpy_size;
//  Printf("Reallocate "PP" (%ld) => "PP" (%ld)\n", old_ptr, old_size, new_ptr, new_size);
//  stack->PrintStack();
  return new_ptr;
}

}  // namespace

void *__asan_memalign(size_t alignment, size_t size, AsanStackTrace *stack) {
  return (void*)Allocate(alignment, size, stack);
}

void __asan_free(void *ptr, AsanStackTrace *stack) {
  Deallocate((uint8_t*)ptr, stack);
}

void *__asan_malloc(size_t size, AsanStackTrace *stack) {
  return (void*)Allocate(0, size, stack);
}

void *__asan_calloc(size_t nmemb, size_t size, AsanStackTrace *stack) {
  uint8_t *res = Allocate(0, nmemb * size, stack);
  memset(res, 0, nmemb * size);
  //asan_clear_mem((uintptr_t*)res, (nmemb * size + kWordSize - 1) / kWordSize);
  return (void*)res;
}
void *__asan_realloc(void *p, size_t size, AsanStackTrace *stack) {
  return Reallocate((uint8_t*)p, size, stack);
}

void *__asan_valloc(size_t size, AsanStackTrace *stack) {
  return Allocate(kPageSize, size, stack);
}

int __asan_posix_memalign(void **memptr, size_t alignment, size_t size,
                          AsanStackTrace *stack) {
  *memptr = Allocate(alignment, size, stack);
  CHECK(((uintptr_t)*memptr % alignment) == 0);
  return 0;
}

size_t __asan_mz_size(const void *ptr) {
  CHECK(0);
  return 0;
}

void __asan_describe_heap_address(uintptr_t addr, uintptr_t access_size) {
  Describe(addr, access_size);
}
