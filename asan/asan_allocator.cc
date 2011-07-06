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

#include "asan_allocator.h"
#include "asan_int.h"
#include "asan_mapping.h"
#include "asan_stats.h"
#include "asan_thread.h"

#include <sys/mman.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <algorithm>


static const size_t kRedzone      = kMinRedzone;
static const size_t kMinAllocSize = kRedzone * 2;
static const size_t kMinMmapSize  = kPageSize * 1024;
static const uint64_t kMaxAvailableRam = 32ULL << 30;  // 32G
static const size_t kMaxThreadLocalQuarantine = 1 << 20;  // 1M
static const size_t kMaxSizeForThreadLocalFreeList = 1 << 17;

static void ShowStatsAndAbort() {
  __asan_stats.PrintStats();
  abort();
}

static void OutOfMemoryMessage(const char *mem_type, size_t size) {
  Printf("==%d== ERROR: AddressSanitizer failed to allocate "
         "0x%lx (%ld) bytes (%s) in T%d\n",
         getpid(), size, size, mem_type, AsanThread::GetCurrent()->tid());
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
  CHECK(IsAligned(mem,        SHADOW_GRANULARITY));
  CHECK(IsAligned(mem + size, SHADOW_GRANULARITY));
  uintptr_t shadow_beg = MemToShadow(mem);
  uintptr_t shadow_end = MemToShadow(mem + size);
  if (poison && SHADOW_GRANULARITY == 128)
    poison = 0xff;
  memset((void*)shadow_beg, poison, shadow_end - shadow_beg);
}

// Given kRedzone bytes, we need to mark first size bytes
// as addressable and the rest kRedzone-size bytes as unaddressable.
static void PoisonMemoryPartialRightRedzone(uintptr_t mem, size_t size) {
  CHECK(size <= kRedzone);
  CHECK(IsAligned(mem, kRedzone));
  CHECK(IsPowerOfTwo(SHADOW_GRANULARITY));
  CHECK(IsPowerOfTwo(kRedzone));
  CHECK(kRedzone >= SHADOW_GRANULARITY);
  uint8_t *shadow = (uint8_t*)MemToShadow(mem);
  PoisonShadowPartialRightRedzone(shadow, size,
                                  kRedzone, SHADOW_GRANULARITY, 0xfa);
}

static size_t total_mmaped = 0;

static uint8_t *MmapNewPagesAndPoisonShadow(size_t size) {
  CHECK((size % kPageSize) == 0);
  uint8_t *res = (uint8_t*)__asan_mmap(0, size,
                   PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANON, -1, 0);
  total_mmaped += size;
  if (res == (uint8_t*)-1) {
    OutOfMemoryMessage(__FUNCTION__, size);
    AsanStackTrace::PrintCurrent();
    abort();
  }
  PoisonShadow((uintptr_t)res, size, 0xff);
  return res;
}

// Every chunk of memory allocated by this allocator can be in one of 3 states:
// CHUNK_AVAILABLE: the chunk is in the free list and ready to be allocated.
// CHUNK_ALLOCATED: the chunk is allocated and not yet freed.
// CHUNK_QUARANTINE: the chunk was freed and put into quarantine zone.
//
// The pseudo state CHUNK_MEMALIGN is used to mark that the address is not
// the beginning of a AsanChunk (in which case 'next' contains the address
// of the AsanChunk).
//
// The magic numbers for the enum values are taken randomly.
enum {
  CHUNK_AVAILABLE  = 0x573B5CE5,
  CHUNK_ALLOCATED  = 0x32041A36,
  CHUNK_QUARANTINE = 0x1978BAE3,
  CHUNK_MEMALIGN   = 0xDC68ECD8,
};

struct ChunkBase {
  uint32_t     chunk_state;
  uint32_t     size;  // Must be power of two
  uint32_t     used_size;
  uint32_t     offset;  // User-visible memory starts at this+offset (beg()).
  int32_t      alloc_tid;
  int32_t      free_tid;
  AsanChunk       *next;

  uintptr_t   beg() { return (uintptr_t)this + offset; }
};

struct AsanChunk: public ChunkBase {
  uint32_t compressed_alloc_stack[(kRedzone - sizeof(ChunkBase)) / sizeof(uint32_t)];
  uint32_t compressed_free_stack[kRedzone / sizeof(uint32_t)];

  bool AddrIsInside(uintptr_t addr, size_t access_size, size_t *offset) {
    if (addr >= beg() && (addr + access_size) <= (beg() + used_size)) {
      *offset = addr - beg();
      return true;
    }
    return false;
  }

  bool AddrIsAtLeft(uintptr_t addr, size_t access_size, size_t *offset) {
    if (addr >= (uintptr_t)this && addr < beg()) {
      *offset = beg() - addr;
      return true;
    }
    return false;
  }

  bool AddrIsAtRight(uintptr_t addr, size_t access_size, size_t *offset) {
    if (addr + access_size >= beg() + used_size &&
        addr < (uintptr_t)this + size + kRedzone) {
      if (addr <= beg() + used_size)
        *offset = 0;
      else
        *offset = addr - (beg() + used_size);
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
    Printf(" %ld-byte region ["PP","PP")\n" , used_size, beg(), beg() + used_size);
  }
};

static AsanChunk *PtrToChunk(uintptr_t ptr) {
  AsanChunk *m = (AsanChunk*)(ptr - kRedzone);
  if (m->chunk_state == CHUNK_MEMALIGN) {
    m = m->next;
  }
  return m;
}


void AsanChunkFifoList::Push(AsanChunkFifoList *q) {
  if (last_) {
    CHECK(first_);
    CHECK(!last_->next);
    last_->next = q->first_;
    last_ = q->last_;
  } else {
    CHECK(!first_);
    last_ = q->last_;
    first_ = q->first_;
  }
  size_ += q->size();
  q->clear();
}

void AsanChunkFifoList::Push(AsanChunk *n) {
  if (last_) {
    CHECK(first_);
    CHECK(!last_->next);
    last_->next = n;
    last_ = n;
  } else {
    CHECK(!first_);
    last_ = first_ = n;
  }
  size_ += n->size;
}

AsanChunk *AsanChunkFifoList::Pop() {
  CHECK(first_);
  AsanChunk *res = first_;
  first_ = first_->next;
  if (first_ == NULL)
    last_ = NULL;
  CHECK(size_ >= res->size);
  size_ -= res->size;
  return res;
}

static size_t GetChunkIdx(size_t size) {
  CHECK(IsPowerOfTwo(size));
  size_t res = Log2(size);
  CHECK(res < kNumFreeLists);
  return res;
}

namespace {

// All pages we ever allocated.
struct PageGroup {
  uintptr_t beg;
  uintptr_t end;
  size_t size_of_chunk;
  bool InRange(uintptr_t addr) {
    return addr >= beg && addr < end;
  }
};



class MallocInfo {
 public:
  AsanChunk *AllocateChunks(size_t size, size_t n_chunks) {
    size_t idx = GetChunkIdx(size);
    AsanChunk *m = NULL;
    AsanChunk **fl = &free_lists_[idx];
    {
      ScopedLock lock(&mu_);
      for (size_t i = 0; i < n_chunks; i++) {
        if (!(*fl)) {
          *fl = GetNewChunks(size);
        }
        AsanChunk *t = *fl;
        *fl = t->next;
        t->next = m;
        CHECK(t->chunk_state == CHUNK_AVAILABLE);
        m = t;
      }
    }
    return m;
  }

  void SwallowThreadLocalMallocStorage(AsanThreadLocalMallocStorage *x,
                                       bool eat_free_lists) {
    CHECK(__asan_flag_quarantine_size > 0);

    ScopedLock lock(&mu_);
    AsanChunkFifoList *q = &x->quarantine_;
    if (q->size() > 0) {
      quarantine_.Push(q);
      while (quarantine_.size() > __asan_flag_quarantine_size) {
        Pop();
      }
    }
    if (eat_free_lists) {
      for (size_t idx = 0; idx < kNumFreeLists; idx++) {
        AsanChunk *m = x->free_lists_[idx];
        while (m) {
          AsanChunk *t = m->next;
          m->next = free_lists_[idx];
          free_lists_[idx] = m;
          m = t;
        }
      }
    }
  }

  AsanChunk *FindMallocedOrFreed(uintptr_t addr, size_t access_size) {
    ScopedLock lock(&mu_);
    return FindChunkByAddr(addr);
  }

  // TODO(glider): AllocationSize() may become very slow if the size of
  // page_groups_ grows. This can be fixed by increasing kMinMmapSize,
  // but a better solution is to speed up the search somehow.
  size_t AllocationSize(uintptr_t ptr) {
    ScopedLock lock(&mu_);

    // first, check if this is our memory
    PageGroup *g = FindPageGroup(ptr);
    if (!g) return 0;
    AsanChunk *m = PtrToChunk(ptr);
    if (m->chunk_state == CHUNK_ALLOCATED) {
      return m->used_size;
    } else {
      return 0;
    }
  }

  void PrintStatus() {
    ScopedLock lock(&mu_);
    size_t malloced = 0;

    Printf(" MallocInfo: in quarantine: %ld malloced: %ld; ",
           quarantine_.size() >> 20, malloced >> 20);
    for (size_t j = 1; j < kNumFreeLists; j++) {
      AsanChunk *i = free_lists_[j];
      if (!i) continue;
      size_t t = 0;
      for (; i; i = i->next) {
        t += i->size;
      }
      Printf("%ld:%ld ", j, t >> 20);
    }
    Printf("\n");
  }

 private:
  PageGroup *FindPageGroup(uintptr_t addr) {
    for (size_t i = 0; i < n_page_groups_; i++) {
      PageGroup *g = page_groups_[i];
      if (g->InRange(addr)) {
        return g;
      }
    }
    return NULL;
  }

  AsanChunk *FindChunkByAddr(uintptr_t addr) {
    PageGroup *g = FindPageGroup(addr);
    if (!g) return 0;
    CHECK(g->size_of_chunk);
    CHECK(IsPowerOfTwo(g->size_of_chunk));
    uintptr_t offset_from_beg = addr - g->beg;
    uintptr_t this_chunk_addr = g->beg +
        (offset_from_beg / g->size_of_chunk) * g->size_of_chunk;
    CHECK(g->InRange(this_chunk_addr));
    AsanChunk *m = (AsanChunk*)this_chunk_addr;
    CHECK(m->chunk_state == CHUNK_ALLOCATED ||
          m->chunk_state == CHUNK_AVAILABLE ||
          m->chunk_state == CHUNK_QUARANTINE);
    uintptr_t offset;
    if (m->AddrIsInside(addr, 1, &offset) ||
        m->AddrIsAtRight(addr, 1, &offset))
      return m;
    bool is_at_left = m->AddrIsAtLeft(addr, 1, &offset);
    CHECK(is_at_left);
    if (this_chunk_addr == g->beg) {
      // leftmost chunk
      return m;
    }
    uintptr_t left_chunk_addr = this_chunk_addr - g->size_of_chunk;
    CHECK(g->InRange(left_chunk_addr));
    AsanChunk *l = (AsanChunk*)left_chunk_addr;
    uintptr_t l_offset;
    bool is_at_right = l->AddrIsAtRight(addr, 1, &l_offset);
    CHECK(is_at_right);
    if (l_offset < offset) {
      return l;
    }
    return m;
  }

  void Pop() {
    CHECK(quarantine_.size() > 0);
    AsanChunk *m = quarantine_.Pop();
    CHECK(m);
    // if (F_v >= 2) Printf("MallocInfo::pop %p\n", m);

    CHECK(m->chunk_state == CHUNK_QUARANTINE);
    m->chunk_state = CHUNK_AVAILABLE;
    CHECK(m->alloc_tid >= 0);
    CHECK(m->free_tid >= 0);
    // TODO(kcc): doing Unref will lead to deadlock.
    // AsanThread::FindByTid(m->alloc_tid)->Unref();
    // AsanThread::FindByTid(m->free_tid)->Unref();

    size_t idx = GetChunkIdx(m->size);
    m->next = free_lists_[idx];
    free_lists_[idx] = m;

    if (__asan_flag_stats) {
      __asan_stats.real_frees++;
      __asan_stats.really_freed += m->used_size;
      __asan_stats.really_freed_by_size[Log2(m->size)]++;
    }
  }

  // Get a list of newly allocated chunks.
  AsanChunk *GetNewChunks(size_t size) {
    CHECK(size <= (1UL << 31));
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
    if (__asan_flag_stats) {
      __asan_stats.mmaps++;
      __asan_stats.mmaped += mmap_size;
      __asan_stats.mmaped_by_size[Log2(size)] += n_chunks;
    }
    AsanChunk *res = NULL;
    for (size_t i = 0; i < n_chunks; i++) {
      AsanChunk *m = (AsanChunk*)(mem + i * size);
      m->chunk_state = CHUNK_AVAILABLE;
      m->size = size;
      m->next = res;
      res = m;
    }
    PageGroup *pg = (PageGroup*)(mem + n_chunks * size);
    // This memory is already poisoned, no need to poison it again.
    pg->beg = (uintptr_t)mem;
    pg->end = pg->beg + mmap_size;
    pg->size_of_chunk = size;
    size_t page_group_idx = AtomicInc(&n_page_groups_) - 1;
    CHECK(page_group_idx < ASAN_ARRAY_SIZE(page_groups_));
    page_groups_[page_group_idx] = pg;
    return res;
  }

  AsanChunk *free_lists_[kNumFreeLists];
  AsanChunkFifoList quarantine_;
  AsanLock mu_;

  PageGroup *page_groups_[kMaxAvailableRam / kMinMmapSize];
  size_t n_page_groups_;  // atomic
};

static MallocInfo malloc_info;

}  // namespace

void AsanThreadLocalMallocStorage::CommitBack() {
  malloc_info.SwallowThreadLocalMallocStorage(this, true);
}

static void Describe(uintptr_t addr, size_t access_size) {
  AsanChunk *m = malloc_info.FindMallocedOrFreed(addr, access_size);
  if (!m) return;
  m->DescribeAddress(addr, access_size);
  CHECK(m->alloc_tid >= 0);
  AsanThread *alloc_thread = AsanThread::FindByTid(m->alloc_tid);
  AsanStackTrace alloc_stack;
  AsanStackTrace::UncompressStack(&alloc_stack, m->compressed_alloc_stack,
                                  ASAN_ARRAY_SIZE(m->compressed_alloc_stack));

  if (m->free_tid >= 0) {
    AsanThread *free_thread = AsanThread::FindByTid(m->free_tid);
    Printf("freed by thread T%d here:\n", free_thread->tid());
    AsanStackTrace free_stack;
    AsanStackTrace::UncompressStack(&free_stack, m->compressed_free_stack,
                                    ASAN_ARRAY_SIZE(m->compressed_free_stack));
    free_stack.PrintStack();
    Printf("previously allocated by thread T%d here:\n",
           alloc_thread->tid());

    alloc_stack.PrintStack();
    AsanThread::GetCurrent()->Announce();
    free_thread->Announce();
    alloc_thread->Announce();
  } else {
    Printf("allocated by thread T%d here:\n", alloc_thread->tid());
    alloc_stack.PrintStack();
    AsanThread::GetCurrent()->Announce();
    alloc_thread->Announce();
  }
}

static uint8_t *Allocate(size_t alignment, size_t size, AsanStackTrace *stack) {
  __asan_init();
  CHECK(stack);
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
  if (needed_size > __asan_flag_large_malloc) {
    OutOfMemoryMessage(__FUNCTION__, size);
    stack->PrintStack();
    abort();
  }
  size_t size_to_allocate = RoundUpToPowerOfTwo(needed_size);
  CHECK(size_to_allocate >= kMinAllocSize);
  CHECK((size_to_allocate % kRedzone) == 0);

  if (__asan_flag_stats) {
    __asan_stats.allocated_since_last_stats += size;
    __asan_stats.mallocs++;
    __asan_stats.malloced += size;
    __asan_stats.malloced_redzones += size_to_allocate - size;
    __asan_stats.malloced_by_size[Log2(size_to_allocate)]++;
    if (__asan_stats.allocated_since_last_stats > (1U << __asan_flag_stats)) {
      __asan_stats.PrintStats();
      malloc_info.PrintStatus();
      __asan_stats.allocated_since_last_stats = 0;
    }
  }

  AsanThread *t = AsanThread::GetCurrent();
  AsanChunk *m = NULL;
  if (size_to_allocate >= kMaxSizeForThreadLocalFreeList) {
    // get directly from global storage.
    m = malloc_info.AllocateChunks(size_to_allocate, 1);
    if (__asan_flag_stats)  __asan_stats.malloc_large++;
  } else {
    // get from the thread-local storage.
    size_t idx = GetChunkIdx(size_to_allocate);
    AsanChunk **fl = &t->malloc_storage().free_lists_[idx];
    if (!*fl) {
      size_t n_new_chunks = kMaxSizeForThreadLocalFreeList / size_to_allocate;
      // n_new_chunks = std::min((size_t)32, n_new_chunks);
      *fl = malloc_info.AllocateChunks(size_to_allocate, n_new_chunks);
      if (__asan_flag_stats) __asan_stats.malloc_small_slow++;
    }
    m = *fl;
    *fl = (*fl)->next;
  }
  CHECK(m);
  CHECK(m->chunk_state == CHUNK_AVAILABLE);
  m->chunk_state = CHUNK_ALLOCATED;
  m->next = NULL;
  CHECK(m->size == size_to_allocate);
  uintptr_t addr = (uintptr_t)m + kRedzone;
  CHECK(addr == (uintptr_t)m->compressed_free_stack);

  if (alignment > kRedzone && (addr & (alignment - 1))) {
    addr = RoundUpTo(addr, alignment);
    CHECK((addr & (alignment - 1)) == 0);
    AsanChunk *p = (AsanChunk*)(addr - kRedzone);
    p->chunk_state = CHUNK_MEMALIGN;
    p->next = m;
  }
  CHECK(m == PtrToChunk(addr));
  m->used_size = size;
  m->offset = addr - (uintptr_t)m;
  CHECK(m->beg() == addr);
  m->alloc_tid = t->Ref()->tid();
  m->free_tid   = -1;
  AsanStackTrace::CompressStack(stack, m->compressed_alloc_stack,
                                ASAN_ARRAY_SIZE(m->compressed_alloc_stack));
  PoisonShadow(addr, rounded_size, 0);
  if (size < rounded_size) {
    PoisonMemoryPartialRightRedzone(addr + rounded_size - kRedzone, size % kRedzone);
  }
  return (uint8_t*)addr;
}

static void Deallocate(uint8_t *ptr, AsanStackTrace *stack) {
  if (!ptr) return;
  CHECK(stack);

  //Printf("Deallocate "PP"\n", ptr);
  AsanChunk *m = PtrToChunk((uintptr_t)ptr);
  if (m->chunk_state == CHUNK_QUARANTINE) {
    Printf("attempting double-free on %p:\n", ptr);
    stack->PrintStack();
    m->DescribeAddress((uintptr_t)ptr, 1);
    ShowStatsAndAbort();
  } else if (m->chunk_state != CHUNK_ALLOCATED) {
    Printf("attempting free on address which was not malloc()-ed: %p\n", ptr);
    stack->PrintStack();
    ShowStatsAndAbort();
  }
  CHECK(m->chunk_state == CHUNK_ALLOCATED);
  CHECK(m->free_tid == -1);
  CHECK(m->alloc_tid >= 0);
  AsanThread *t = AsanThread::GetCurrent();
  m->free_tid = t->Ref()->tid();
  AsanStackTrace::CompressStack(stack, m->compressed_free_stack,
                                ASAN_ARRAY_SIZE(m->compressed_free_stack));
  size_t rounded_size = RoundUpTo(m->used_size, kRedzone);
  PoisonShadow((uintptr_t)ptr, rounded_size, 0xfb);

  if (__asan_flag_stats) {
    __asan_stats.frees++;
    __asan_stats.freed += m->used_size;
    __asan_stats.freed_by_size[Log2(m->size)]++;
  }

  m->chunk_state = CHUNK_QUARANTINE;
  AsanThreadLocalMallocStorage *ms = &t->malloc_storage();
  ms->quarantine_.Push(m);

  if (ms->quarantine_.size() > kMaxThreadLocalQuarantine) {
    malloc_info.SwallowThreadLocalMallocStorage(ms, false);
  }
}

static uint8_t *Reallocate(uint8_t *old_ptr, size_t new_size, AsanStackTrace *stack) {
  if (!old_ptr) {
    return Allocate(0, new_size, stack);
  }
  if (new_size == 0) {
    return NULL;
  }
  if (__asan_flag_stats) {
    __asan_stats.reallocs++;
    __asan_stats.realloced += new_size;
  }
  AsanChunk *m = PtrToChunk((uintptr_t)old_ptr);
  CHECK(m->chunk_state == CHUNK_ALLOCATED);
  size_t old_size = m->used_size;
  size_t memcpy_size = std::min(new_size, old_size);
  uint8_t *new_ptr = Allocate(0, new_size, stack);
  memcpy(new_ptr, old_ptr, memcpy_size);
  Deallocate(old_ptr, stack);
  __asan_stats.reallocs++;
  __asan_stats.realloced += memcpy_size;
//  Printf("Reallocate "PP" (%ld) => "PP" (%ld)\n", old_ptr, old_size, new_ptr, new_size);
//  stack->PrintStack();
  return new_ptr;
}

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
  return malloc_info.AllocationSize((uintptr_t)ptr);
}

void __asan_describe_heap_address(uintptr_t addr, uintptr_t access_size) {
  Describe(addr, access_size);
}
size_t __asan_total_mmaped() {
  return total_mmaped;
}
