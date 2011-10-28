//===-- asan_malloc_linux.cc ------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file is a part of AddressSanitizer, an address sanity checker.
//
// Linux-specific malloc interception.
// We simply define functions like malloc, free, realloc, etc.
// They will replace the corresponding libc functions automagically.
//===----------------------------------------------------------------------===//

#include "asan_allocator.h"
#include "asan_interceptors.h"
#include "asan_internal.h"
#include "asan_stack.h"

#include <malloc.h>

#define INTERCEPTOR_ATTRIBUTE __attribute__((visibility("default")))

namespace __asan {
void ReplaceSystemMalloc() {
}
}  // namespace __asan

// ---------------------- Replacement functions ---------------- {{{1
using namespace __asan;  // NOLINT

extern "C" {
INTERCEPTOR_ATTRIBUTE
void free(void *ptr) {
  GET_STACK_TRACE_HERE_FOR_FREE(ptr);
  __asan_free(ptr, &stack);
}

INTERCEPTOR_ATTRIBUTE
void cfree(void *ptr) {
  GET_STACK_TRACE_HERE_FOR_FREE(ptr);
  __asan_free(ptr, &stack);
}

INTERCEPTOR_ATTRIBUTE
void *malloc(size_t size) {
  GET_STACK_TRACE_HERE_FOR_MALLOC;
  return __asan_malloc(size, &stack);
}

INTERCEPTOR_ATTRIBUTE
void *calloc(size_t nmemb, size_t size) {
  if (!__asan_inited) {
    // Hack: dlsym calls calloc before real_calloc is retrieved from dlsym.
    const size_t kCallocPoolSize = 1024;
    static uintptr_t calloc_memory_for_dlsym[kCallocPoolSize];
    static size_t allocated;
    size_t size_in_words = ((nmemb * size) + kWordSize - 1) / kWordSize;
    void *mem = (void*)&calloc_memory_for_dlsym[allocated];
    allocated += size_in_words;
    CHECK(allocated < kCallocPoolSize);
    return mem;
  }
  GET_STACK_TRACE_HERE_FOR_MALLOC;
  return __asan_calloc(nmemb, size, &stack);
}

INTERCEPTOR_ATTRIBUTE
void *realloc(void *ptr, size_t size) {
  GET_STACK_TRACE_HERE_FOR_MALLOC;
  return __asan_realloc(ptr, size, &stack);
}

INTERCEPTOR_ATTRIBUTE
void *memalign(size_t boundary, size_t size) {
  GET_STACK_TRACE_HERE_FOR_MALLOC;
  return __asan_memalign(boundary, size, &stack);
}

void* __libc_memalign(size_t align, size_t s)
  __attribute__((alias("memalign")));

INTERCEPTOR_ATTRIBUTE
struct mallinfo mallinfo() {
  struct mallinfo res;
  real_memset(&res, 0, sizeof(res));
  return res;
}

INTERCEPTOR_ATTRIBUTE
int mallopt(int cmd, int value) {
  return -1;
}

INTERCEPTOR_ATTRIBUTE
int posix_memalign(void **memptr, size_t alignment, size_t size) {
  GET_STACK_TRACE_HERE_FOR_MALLOC;
  // Printf("posix_memalign: %lx %ld\n", alignment, size);
  return __asan_posix_memalign(memptr, alignment, size, &stack);
}

INTERCEPTOR_ATTRIBUTE
void *valloc(size_t size) {
  GET_STACK_TRACE_HERE_FOR_MALLOC;
  return __asan_valloc(size, &stack);
}

INTERCEPTOR_ATTRIBUTE
void *pvalloc(size_t size) {
  GET_STACK_TRACE_HERE_FOR_MALLOC;
  return __asan_pvalloc(size, &stack);
}
}  // extern "C"
