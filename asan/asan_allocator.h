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

#include "asan_int.h"

extern "C" {
void *__asan_memalign(size_t size, size_t alignment, AsanStackTrace *stack);
void __asan_free(void *ptr, AsanStackTrace *stack);

void *__asan_malloc(size_t size, AsanStackTrace *stack);
void *__asan_calloc(size_t nmemb, size_t size, AsanStackTrace *stack);
void *__asan_realloc(void *p, size_t size, AsanStackTrace *stack);
void *__asan_valloc(size_t size, AsanStackTrace *stack);

int __asan_posix_memalign(void **memptr, size_t alignment, size_t size,
                          AsanStackTrace *stack);

size_t __asan_mz_size(void *ptr);
void __asan_describe_heap_address(uintptr_t addr, size_t access_size);

// to be deprecated
extern void *(*__asan_real_malloc)(size_t);
extern void (*__asan_real_free)(void *ptr);

}  // extern "C"
