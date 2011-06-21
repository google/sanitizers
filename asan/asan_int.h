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

#ifndef ASAN_INT_H
#define ASAN_INT_H

#include "asan_rtl.h"
#include <stdint.h>  // for __WORDSIZE
#include <stdlib.h>  // for size_t

static const int kMinRedzone = 128;

class AsanThread;
class AsanStackTrace;

extern "C" {
void *__asan_memalign(size_t size, size_t alignment,
                      AsanThread *thread, AsanStackTrace *stack);
void __asan_free(void *ptr, AsanThread *thread, AsanStackTrace *stack);


void __asan_printf(const char *format, ...);
void __asan_check_failed(const char *cond, const char *file, int line);

extern size_t __asan_flag_quarantine_size;
extern int    __asan_flag_demangle;
extern bool   __asan_flag_symbolize;

}  // extern "C"

#define Printf __asan_printf

#define CHECK(cond) do { if (!(cond)) { \
  __asan_check_failed(#cond, __FILE__, __LINE__); \
}}while(0)

#ifdef __APPLE__
static const bool __asan_need_real_malloc = false;
#else
extern __thread bool __asan_need_real_malloc;
#endif

const size_t kWordSize = __WORDSIZE / 8;
const size_t kWordSizeInBits = 8 * kWordSize;
const size_t kPageSizeBits = 12;
const size_t kPageSize = 1UL << kPageSizeBits;


#endif  // ASAN_INT_H
