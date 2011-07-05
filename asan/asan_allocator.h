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
  void Push(AsanChunk*);
  void Push(AsanChunkFifoList *);
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
  AsanChunkFifoList quarantine_;
  void CommitBack();
};

extern "C" {
void *__asan_memalign(size_t alignment, size_t size, AsanStackTrace *stack);
void __asan_free(void *ptr, AsanStackTrace *stack);

void *__asan_malloc(size_t size, AsanStackTrace *stack);
void *__asan_calloc(size_t nmemb, size_t size, AsanStackTrace *stack);
void *__asan_realloc(void *p, size_t size, AsanStackTrace *stack);
void *__asan_valloc(size_t size, AsanStackTrace *stack);

int __asan_posix_memalign(void **memptr, size_t alignment, size_t size,
                          AsanStackTrace *stack);

size_t __asan_mz_size(const void *ptr);
void __asan_describe_heap_address(uintptr_t addr, size_t access_size);

size_t __asan_total_mmaped();

}  // extern "C"
#endif  // ASAN_ALLOCATOR_H
