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

// This file is deprecated and will be deleted soon.

#include "asan_allocator.h"
#include "asan_int.h"
#include "asan_lock.h"
#include "asan_mapping.h"
#include "asan_stack.h"
#include "asan_stats.h"
#include "asan_thread.h"

#include <string.h>
#include <algorithm>
#include <unistd.h>

void *(*__asan_real_malloc)(size_t);
void (*__asan_real_free)(void *ptr);

namespace {

static void ShowStatsAndAbort() {
  __asan_stats.PrintStats();
  abort();
}

static void OutOfMemoryMessage(const char *mem_type, size_t size) {
  Printf("==%d== ERROR: AddressSanitizer failed to allocate "
         "0x%lx (%ld) bytes of %s\n",
         getpid(), size, size, mem_type);
}

struct Ptr {
  uint32_t magic;
  uint32_t orig_libc_offset;
  size_t size;
  Ptr    *next;
  Ptr    *prev;
  AsanThread *malloc_thread;
  AsanThread *free_thread;

  static const uint32_t kMallocedMagic   = 0x45DEAA11;
  static const uint32_t kAsanPtrMagic    = 0xA5A4A5A4;
  static const uint32_t kFreedMagic      = 0x94B06185;
  static const uint32_t kRealyFreedMagic = 0xDEAD1234;

  uintptr_t orig_libc_ptr() {
    return (uintptr_t)(this) - (uintptr_t)orig_libc_offset;
  }

  static size_t ReservedWords() { return sizeof(Ptr) / kWordSize; }

  size_t size_in_words() { return size_in_words(size); }
  size_t real_size_in_words() { return real_size_in_words(size); }

  uintptr_t rz1_beg() { return (uintptr_t)this; }
  uintptr_t rz1_end() { return rz1_beg() + __asan_flag_redzone_words * kWordSize; }
  uintptr_t beg()     {
    CHECK((rz1_end() % 8) == 0);
    return rz1_end();
  }
  uintptr_t end()     { return beg() + size; }
  uintptr_t rz2_beg() { return end(); }
  uintptr_t rz2_end() { return end() + __asan_flag_redzone_words * kWordSize; }
  void     *raw_ptr() { return (void*)beg(); }

  bool InRange(uintptr_t p) { return p >= rz1_beg() && p < rz2_end(); }
  bool InRz1(uintptr_t p)   { return p >= rz1_beg() && p < rz1_end(); }
  bool InRz2(uintptr_t p)   { return p >= rz2_beg() && p < rz2_end(); }
  bool InAllocated(uintptr_t p) { return p >= beg() && p < end(); }

  uintptr_t &at(size_t i) {
    return ((uintptr_t*)this)[i];
  }

  void PrintOneLine(const char *before = "", const char *after = "\n") {
    Printf(
            "%s["PP","PP"); red zones: ["PP","PP"), ["PP","PP");"
            " size=%ld (0x%lx)%s",
            before,
            beg(), end(), rz1_beg(), rz1_end(), rz2_beg(), rz2_end(),
            size, size,
            after);
  }

  void PrintRaw(int where) {
    Printf("this=%p magic=%x orig_libc_offset=%x size=%lx "
           "next=%p prev=%p mt=%p ft=%p where=%d\n",
           this, magic, orig_libc_offset, size,
           next, prev, malloc_thread, free_thread, where);
  }

  void DescribeAddress(uintptr_t addr, size_t access_size) {
    CHECK(InRange(addr));
    Printf(""PP" is located ", addr);
    if (InRz1(addr)) {
      Printf("%ld bytes to the left of", rz1_end() - addr);
    } else if (InRz2(addr) || InRz2(addr + access_size - 1)) {
      uintptr_t offset = addr - rz2_beg();
      if (addr < rz2_beg()) {
        CHECK(addr + access_size > rz2_beg());
        offset = 0;
      }
      Printf("%ld bytes to the right of", offset);
    } else {
      CHECK(InAllocated(addr));
      Printf("%ld bytes inside of", addr - beg());
    }
    Printf(" %ld-byte region ["PP","PP")\n" , size, beg(), end());
    if (__asan_flag_debug) {
      Printf("["PP","PP") -- left red zone\n", rz1_beg(), rz1_end());
      Printf("["PP","PP") -- right red zone\n", rz2_beg(), rz2_end());
    }
  }

  void CompactPoisonRegion(uintptr_t beg, uintptr_t end, uint64_t poison) {
    uint8_t *beg_ptr = (uint8_t*)MemToShadow(beg);
    uint8_t *end_ptr = (uint8_t*)MemToShadow(end);
    for (; beg_ptr < end_ptr; beg_ptr++)
      *beg_ptr = poison;
  }

  void CompactPoison(uint64_t poison_left,
                     uint64_t poison_main, uint64_t poison_right) {
    CompactPoisonRegion(rz1_beg(), rz1_end(), poison_left);
    CompactPoisonRegion(rz2_beg(), rz2_end(), poison_right);
    CompactPoisonRegion(    beg(),     end(), poison_main);
    if ((size % 8) && poison_right != 0 && poison_main == 0) {
      // one of the shadow bytes should be half-poisoned.
      uintptr_t last_qword = end();
      size_t addressible_bytes = size % 8;
      CHECK(addressible_bytes == (last_qword % 8));
      CHECK(addressible_bytes > 0 && addressible_bytes < 8);
      uint8_t *last_shadow = (uint8_t*)MemToShadow(last_qword);
      *last_shadow = addressible_bytes;
    }
  }

  __attribute__((noinline))
  void PoisonOnMalloc() {
    if (!__asan_flag_poison_shadow) return;
    CompactPoison(0xa0a1a2a3a4a5a6a7ULL, 0,
                  0xb0b1b2b3b4b5b6b7ULL);
  }


  __attribute__((noinline))
  void PoisonOnFree(uintptr_t poison) {
    if (!__asan_flag_poison_shadow) return;
    CHECK(AddrIsInMem(rz1_beg()));
    if (poison) {
      CompactPoison(0xc0c1c2c3c4c5c6c7ULL,
                    0xd0d1d2d3d4d5d6d7ULL,
                    0xe0e1e2e3e4e5e6e7ULL);
    } else {
      uint8_t *beg = (uint8_t*)MemToShadow(rz1_beg());
      uint8_t *end = (uint8_t*)MemToShadow(rz2_end());
      memset(beg, 0, end - beg);
    }
  }

  void CopyStackTrace(AsanStackTrace &stack, uintptr_t *dest, size_t max_size) {
    size_t i;
    for (i = 0; i < std::min(max_size, stack.size); i++)
      dest[i] = stack.trace[i];
    if (i < max_size)
      dest[i] = 0;
  }

  uintptr_t *MallocStack() { return  (uintptr_t*)beg() + size_in_words(); }
  size_t MallocStackSize() {
    CHECK(__asan_flag_malloc_context_size <= __asan_flag_redzone_words);
    return __asan_flag_malloc_context_size;
  }
  uintptr_t *FreeStack()    { return (uintptr_t*)rz1_beg() + ReservedWords(); }
  size_t FreeStackSize()   {
    size_t available = size_in_words() + __asan_flag_redzone_words - ReservedWords();
    return std::min(available, __asan_flag_malloc_context_size);
  }

  void CopyStackTraceForMalloc(AsanStackTrace &stack) {
    CopyStackTrace(stack, MallocStack(), MallocStackSize());
  }

  void CopyStackTraceForFree(AsanStackTrace &stack) {
    CopyStackTrace(stack, FreeStack(), FreeStackSize());
  }

  void PrintMallocStack() {
    AsanStackTrace::PrintStack(MallocStack(), MallocStackSize());
  }

  void PrintFreeStack() {
    AsanStackTrace::PrintStack(FreeStack(), FreeStackSize());
  }

  static size_t size_in_words(size_t size) {
    return (size + kWordSize - 1) / kWordSize;
  }
  static size_t real_size_in_words(size_t size) {
    return size_in_words(size) + __asan_flag_redzone_words * 2;
  }
};

class MallocInfo {
 public:
  void print_malloced(const char *where) {
    Printf("%s: malloced:\n", where);
    for (Ptr *i = malloced_items_; i; i = i->next)
      i->PrintOneLine("  ");
  }

  void print_freed(const char *where) {
    Ptr *i = freed_items_;
    Printf("%s: freed:\n", where);
    if (i) do {
      i->PrintOneLine("  ");
      i = i->next;
    } while (i != freed_items_);
  }

  void print_lists(const char *where) {
    ScopedLock lock(&mu_);
    Printf("%s: lists: %p %p\n", where, malloced_items_, freed_items_);
    print_malloced(where);
    print_freed(where);
  }

  void on_malloc(Ptr *p) {
    CHECK(__asan_flag_quarantine_size > 0);
    CHECK(Ptr::ReservedWords() <= 8);
    p->prev = 0;
    p->magic = Ptr::kMallocedMagic;
    p->malloc_thread = AsanThread::GetCurrent()->Ref();
    p->free_thread = 0;
    ScopedLock lock(&mu_);
    if (malloced_items_) {
      malloced_items_->prev = p;
    }
    p->next = malloced_items_;
    malloced_items_ = p;
  }

  void on_free(Ptr *p) {
    CHECK(p);
    size_t real_size_in_words = p->real_size_in_words();
    CHECK(p->magic == Ptr::kMallocedMagic);
    p->magic = Ptr::kFreedMagic;
    p->free_thread = AsanThread::GetCurrent()->Ref();

    ScopedLock lock(&mu_);
    // remove from malloced list.
    {
      if (p == malloced_items_) {
        malloced_items_ = p->next;
        if (malloced_items_)
          malloced_items_->prev = 0;
      } else {
        Ptr *prev = p->prev;
        Ptr *next = p->next;
        if (prev) prev->next = next;
        if (next) next->prev = prev;
      }
    }

    if (!freed_items_) {
      p->next = p->prev = p;
    } else {
      Ptr *prev = freed_items_->prev;
      Ptr *next = freed_items_;
      p->next = next;
      p->prev = prev;
      prev->next = p;
      next->prev = p;
    }
    freed_items_ = p;
    cur_size_ += real_size_in_words * kWordSize;;
    while (cur_size_ && (cur_size_ > __asan_flag_quarantine_size)) {
      pop();
    }
  }

  Ptr *find_freed(uintptr_t p) {
    Ptr *i = freed_items_;
    if (!i) return 0;
    do {
      // Printf("MallocInfo::find %lx in [%lx,%lx)\n",
      //        p, (uintptr_t)i, (uintptr_t)i + i->size);
      if (i->InRange(p))
        return i;
      i = i->next;
    } while (i != freed_items_);
    return 0;
  }

  Ptr *find_malloced(uintptr_t p) {
    for (Ptr *i = malloced_items_; i; i = i->next) {
      if (i->InRange(p)) return i;
    }
    return 0;
  }

  Ptr *safe_find_malloced(uintptr_t p) {
    ScopedLock lock(&mu_);
    return find_malloced(p);
  }

  void DescribeAddress(uintptr_t addr, size_t access_size) {
    ScopedLock lock(&mu_);
    // Check if we have this memory region in delay queue.
    Ptr *freed = find_freed(addr);
    Ptr *malloced = find_malloced(addr);

    if (freed && malloced) {
      Printf("ACHTUNG! the address is listed as both freed and malloced\n");
    }

    if (!freed && !malloced) {
      Printf("ACHTUNG! the address is listed as neither freed nor malloced\n");
    }

    if (freed) {
      if (__asan_flag_v) freed->PrintRaw(__LINE__);
      freed->DescribeAddress(addr, access_size);
      Printf("freed by thread T%d here:\n",
             freed->free_thread->tid());
      freed->PrintFreeStack();
      Printf("previously allocated by thread T%d here:\n",
             freed->malloc_thread->tid());
      freed->PrintMallocStack();
      AsanThread::GetCurrent()->Announce();
      freed->free_thread->Announce();
      freed->malloc_thread->Announce();
      return;
    }

    if (malloced) {
      if (__asan_flag_v) malloced->PrintRaw(__LINE__);
      malloced->DescribeAddress(addr, access_size);
      // size_t kStackSize = 100;
      // uintptr_t stack[kStackSize];
      // size_t stack_size = get_stack_trace_of_malloced_addr(malloced, stack, kStackSize);
      Printf("allocated by thread T%d here:\n",
             malloced->malloc_thread->tid());
      malloced->PrintMallocStack();
      // PrintStack(stack, stack_size);
      AsanThread::GetCurrent()->Announce();
      malloced->malloc_thread->Announce();
      return;
    }
    Printf("Address 0x%lx is not malloc-ed or (recently) freed\n", addr);
  }


 private:
  void pop() {
    CHECK(freed_items_);
    CHECK(cur_size_ > 0);
    Ptr *p = freed_items_->prev;
    CHECK(p);
    // Printf("pop  : %p cur_size_ = %ld; size = %ld\n", p, cur_size_, p->size);
    Ptr *next = p->next;
    Ptr *prev = p->prev;
    CHECK(next && prev);
    if (next == p) {
      freed_items_ = NULL;
    } else {
      next->prev = prev;
      prev->next = next;
    }
    cur_size_ -= p->real_size_in_words() * kWordSize;
    if (__asan_flag_v >= 2) Printf("MallocInfo::pop %p\n", p);
    p->magic = Ptr::kRealyFreedMagic;
    p->PoisonOnFree(0);
    __asan_stats.real_frees++;
    __asan_stats.really_freed += p->real_size_in_words() * kWordSize;
    __asan_real_free((void*)p->orig_libc_ptr());
  }

  size_t cur_size_;
  Ptr *freed_items_;
  Ptr *malloced_items_;
  AsanLock mu_;
};

static MallocInfo malloc_info;

Ptr *asan_memalign(size_t alignment, size_t size, AsanStackTrace &stack) {
  __asan_init();
  CHECK((alignment & (alignment - 1)) == 0);
  CHECK(__asan_flag_redzone_words >= Ptr::ReservedWords());
  size_t real_size_in_words = Ptr::real_size_in_words(size);
  size_t real_size_with_alignment =
      real_size_in_words * kWordSize + alignment;

  if (size >= __asan_flag_large_malloc) {
    Printf("User requested %lu bytes:\n", size);
    stack.PrintStack();
  }
  uintptr_t orig = (uintptr_t)__asan_real_malloc(real_size_with_alignment);

  if (orig == 0) {
    OutOfMemoryMessage("main memory", size);
    stack.PrintStack();
    ShowStatsAndAbort();
  }


  if ((!AddrIsInMem(orig) || !AddrIsInMem(orig + real_size_with_alignment)) && 
      __asan_flag_poison_shadow) {
    Printf("==%d== AddressSanitizer failure: malloc returned ["PP", "PP")\n",
           getpid(), orig, orig + real_size_with_alignment);
    ShowStatsAndAbort();
  }

  uintptr_t orig_beg = orig + __asan_flag_redzone_words * kWordSize;
  uintptr_t beg = orig_beg;

  if (alignment && (beg % alignment) != 0) {
    CHECK(alignment >= kWordSize);
    uintptr_t mod = beg % alignment;
    CHECK(alignment > mod);
    beg += alignment - mod;
    CHECK((beg % alignment) == 0);
  }
  uintptr_t rz1_beg = beg - __asan_flag_redzone_words * kWordSize;

  Ptr *p = (Ptr*)rz1_beg;
  p->size = size;
  p->orig_libc_offset = (uint32_t)(rz1_beg - orig);
  CHECK(p->orig_libc_ptr() == orig);
  CHECK(p->rz1_beg() == rz1_beg);
  CHECK(p->beg() == beg);
  CHECK(p->rz2_end() <= orig + real_size_with_alignment);

  __asan_stats.malloced += real_size_with_alignment;
  __asan_stats.malloced_redzones += __asan_flag_redzone_words * 2 * kWordSize;
  __asan_stats.mallocs++;

  if (__asan_flag_v >= 2)
    p->PrintOneLine("asan_malloc: ");
  p->CopyStackTraceForMalloc(stack);
  malloc_info.on_malloc(p);
  p->PoisonOnMalloc();
  *((uint32_t*)beg - 1) = Ptr::kAsanPtrMagic;
  return p;
}

__attribute__((noinline))
static void check_ptr_on_free(Ptr *p, void *addr, AsanStackTrace &stack) {
  CHECK(p->beg() == (uintptr_t)addr);
  if (p->magic != Ptr::kMallocedMagic) {
    if (p->magic == Ptr::kFreedMagic) {
      Printf("attempting double-free on %p:\n", addr);
      stack.PrintStack();
      malloc_info.DescribeAddress(p->beg(), 1);
      ShowStatsAndAbort();
    } else {
      Printf("attempting free on address which was not malloc()-ed: %p\n",
             addr);
      stack.PrintStack();
      malloc_info.DescribeAddress(p->beg(), 1);
      ShowStatsAndAbort();
    }
  }
}

void asan_free(void *addr, AsanStackTrace &stack) {
  __asan_init();
  if (!addr) return;
  Ptr *p = (Ptr*)((uintptr_t*)addr - __asan_flag_redzone_words);
  size_t real_size_in_words = p->real_size_in_words();
  if (*((uint32_t*)addr - 1) == Ptr::kAsanPtrMagic) {
    // We can't CHECK for kAsanPtrMagic, because it will fail in the double-free case.
    *((uint32_t*)addr - 1) = 0;
  }

  check_ptr_on_free(p, addr, stack);

  if (__asan_flag_v >= 2)
    p->PrintOneLine("asan_free:   ", "\n");

  p->PoisonOnFree(1);
  p->CopyStackTraceForFree(stack);
  malloc_info.on_free(p);

  __asan_stats.frees++;
  __asan_stats.freed += real_size_in_words * kWordSize;
  __asan_stats.freed_since_last_stats += real_size_in_words * kWordSize;


  if (__asan_flag_stats &&
      __asan_stats.freed_since_last_stats > (1U << __asan_flag_stats)) {
    __asan_stats.freed_since_last_stats = 0;
    __asan_stats.PrintStats();
  }
}

__attribute__((noinline))
static void asan_clear_mem(uintptr_t *mem, size_t n_words) {
  for (size_t i = 0; i < n_words; i++)
    mem[i] = 0;
}

void *asan_calloc(size_t nmemb, size_t size, AsanStackTrace &stack) {
  Ptr *p = asan_memalign(0, nmemb * size, stack);
  void *ptr = p->raw_ptr();
  asan_clear_mem((uintptr_t*)ptr, (nmemb * size + kWordSize - 1) / kWordSize);
  return ptr;
}

__attribute__((noinline))
static void asan_copy_mem(uintptr_t *dst, uintptr_t *src, size_t n_words) {
  for (size_t i = 0; i < n_words; i++) {
    dst[i] = src[i];
  }
}

void *asan_realloc(void *addr, size_t size, AsanStackTrace &stack) {
  if (!addr) {
    Ptr *p = asan_memalign(0, size, stack);
    return p->raw_ptr();
  }
  Ptr *p = (Ptr*)((uintptr_t*)addr - __asan_flag_redzone_words);
  check_ptr_on_free(p, addr, stack);
  if (__asan_flag_v >= 2)
    p->PrintOneLine("asan_realloc: ", "\n");
  size_t old_size = p->size;
  Ptr *new_p = asan_memalign(0, size, stack);
  void *new_ptr = new_p->raw_ptr();
  size_t memcpy_size = std::min(size, old_size);
  // memcpy(new_ptr, addr, memcpy_size);
  asan_copy_mem((uintptr_t*)new_ptr, (uintptr_t*)addr,
                (memcpy_size + kWordSize - 1) / kWordSize);
  asan_free(addr, stack);
  __asan_stats.reallocs++;
  __asan_stats.realloced += memcpy_size;
  return new_ptr;
}

}  // namespace

void *__asan_memalign(size_t alignment, size_t size, AsanStackTrace *stack) {
  CHECK((alignment & (alignment - 1)) == 0);
  Ptr *p = asan_memalign(alignment, size, *stack);
  return p->raw_ptr();
}

void __asan_free(void *ptr, AsanStackTrace *stack) {
  asan_free(ptr, *stack);
}

void *__asan_malloc(size_t size, AsanStackTrace *stack) {
  Ptr *p = asan_memalign(0, size, *stack);
  return p->raw_ptr();
}

void *__asan_calloc(size_t nmemb, size_t size, AsanStackTrace *stack) {
  return asan_calloc(nmemb, size, *stack);
}
void *__asan_realloc(void *p, size_t size, AsanStackTrace *stack) {
  return asan_realloc(p, size, *stack);
}

void *__asan_valloc(size_t size, AsanStackTrace *stack) {
  Ptr *p = asan_memalign(kPageSize, size, *stack);
  return p->raw_ptr();
}

int __asan_posix_memalign(void **memptr, size_t alignment, size_t size,
                          AsanStackTrace *stack) {
  Ptr *p = asan_memalign(alignment, size, *stack);
  *memptr = p->raw_ptr();
  CHECK(((uintptr_t)*memptr % alignment) == 0);
  return 0;
}

size_t __asan_mz_size(const void *ptr) {
  // If |ptr| was returned by asan_memalign(), then ptr[-1] is kAsanPtrMagic.
  // The previous four bytes may possibly hit an unmapped page, but this is
  // very unlikely.
  if (*((uint32_t*)ptr-1) == Ptr::kAsanPtrMagic) {
    Ptr *p = (Ptr*)((uintptr_t*)ptr - __asan_flag_redzone_words);
    CHECK(p->magic == Ptr::kMallocedMagic);
    return p->size;
  } else {
    return 0;
  }
#if 0  
  Ptr *p = malloc_info.safe_find_malloced((uintptr_t)ptr);
  if (p) {
    CHECK(p->magic == Ptr::kMallocedMagic);
    return p->size;
  } else {
    // |ptr| doesn't belong to our malloc list.
    return 0;
  }
#endif  
}

void __asan_describe_heap_address(uintptr_t addr, uintptr_t access_size) {
  malloc_info.DescribeAddress(addr, access_size);
}
