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

#ifndef ASAN_ALLOCATOR_H
#define ASAN_ALLOCATOR_H

#include "asan_int.h"

static const size_t kNumFreeLists = __WORDSIZE;
class AsanChunk;

class AsanChunkFifoList {
 public:
  AsanChunkFifoList() { clear(); }
  void Push(AsanChunk *n);
  void PushList(AsanChunkFifoList *q);
  AsanChunk *Pop();
  size_t size() { return size_; }
  void clear() {
    first_ = last_ = NULL;
    size_ = 0;
  }
 private:
  AsanChunk *first_;
  AsanChunk *last_;
  size_t size_;
};


struct AsanThreadLocalMallocStorage {
  AsanThreadLocalMallocStorage() {
    for (size_t i = 0; i < kNumFreeLists; i++)
      free_lists_[i] = 0;
  }

  AsanChunkFifoList quarantine_;
  AsanChunk *free_lists_[kNumFreeLists];
  void CommitBack();
};

// For each thread we create a fake stack and place stack objects on this fake
// stack instead of the real stack. The fake stack is not really a stack but
// a fast malloc-like allocator so that when a function exits the fake stack
// is not poped but remains there for quite some time until gets used again.
// So, we poison the objects on the fake stack when function returns.
// It helps us find use-after-return bugs.
class AsanFakeStack {
 public:
  AsanFakeStack();
  explicit AsanFakeStack(int empty_ctor_for_thread_0) { }
  void Init(size_t stack_size);
  void Cleanup();
  uintptr_t AllocateStack(size_t size);
  void DeallocateStack(uintptr_t ptr, size_t size);
  // Return the bottom of the maped region.
  uintptr_t AddrIsInFakeStack(uintptr_t addr);
 private:
  static const size_t kMinStackFrameSizeLog = 9;  // Min frame is 512B.
  static const size_t kMaxStackFrameSizeLog = 16;  // Max stack frame is 64K.
  static const size_t kMaxStackMallocSize = 1 << kMaxStackFrameSizeLog;
  static const size_t kNumberOfSizeClasses =
      kMaxStackFrameSizeLog - kMinStackFrameSizeLog + 1;

  bool AddrIsInSizeClass(uintptr_t addr, size_t size_class);

  // Each size class should be large enough to hold all frames.
  size_t ClassMmapSize(size_t size_class);

  size_t ClassSize(size_t size_class) {
    return 1UL << (size_class + kMinStackFrameSizeLog);
  }

  size_t ComputeSizeClass(size_t alloc_size);
  void AllocateOneSizeClass(size_t size_class);

  struct FifoNode {
    uintptr_t padding[2];  // Used by the instrumentation code.
    FifoNode *next;
  };

  struct FifoList {
    FifoNode *first, *last;
    void FifoPush(uintptr_t a);
    uintptr_t FifoPop();
  };

  size_t stack_size_;
  bool   alive_;

  uintptr_t allocated_size_classes_[kNumberOfSizeClasses];
  FifoList size_classes_[kNumberOfSizeClasses];
};

extern "C" {
void *__asan_memalign(size_t alignment, size_t size, AsanStackTrace *stack);
void __asan_free(void *ptr, AsanStackTrace *stack);

void *__asan_malloc(size_t size, AsanStackTrace *stack);
void *__asan_calloc(size_t nmemb, size_t size, AsanStackTrace *stack);
void *__asan_realloc(void *p, size_t size, AsanStackTrace *stack);
void *__asan_valloc(size_t size, AsanStackTrace *stack);
void *__asan_pvalloc(size_t size, AsanStackTrace *stack);

int __asan_posix_memalign(void **memptr, size_t alignment, size_t size,
                          AsanStackTrace *stack);

size_t __asan_mz_size(const void *ptr);
void __asan_describe_heap_address(uintptr_t addr, size_t access_size);

size_t __asan_total_mmaped();
}  // extern "C"
#endif  // ASAN_ALLOCATOR_H
