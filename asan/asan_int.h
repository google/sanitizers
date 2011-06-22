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
void __asan_init();
void __asan_printf(const char *format, ...);
void __asan_check_failed(const char *cond, const char *file, int line);
}  // extern "C"

extern size_t __asan_flag_quarantine_size;
extern int    __asan_flag_demangle;
extern bool   __asan_flag_symbolize;
extern int    __asan_flag_v;
extern bool   __asan_flag_mt;
extern size_t __asan_flag_redzone_words;
extern int    __asan_flag_debug;
extern bool   __asan_flag_poison_shadow;
extern size_t __asan_flag_malloc_context_size;
extern int    __asan_flag_stats;
extern uintptr_t __asan_flag_large_malloc;


#define Printf __asan_printf

#if __WORDSIZE == 64
  #define PP "0x%016lx"
#else
  #define PP "0x%08lx"
#endif

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

#define GET_CALLER_PC() (uintptr_t)__builtin_return_address(0)
#define GET_CURRENT_FRAME() (uintptr_t*)__builtin_frame_address(0)

// -------------------------- Atomic ---------------- {{{1
static inline int AtomicInc(int *a) {
  if (!__asan_flag_mt) return ++(*a);
  return __sync_add_and_fetch(a, 1);
}

static inline int AtomicDec(int *a) {
  if (!__asan_flag_mt) return --(*a);
  return __sync_add_and_fetch(a, -1);
}



#endif  // ASAN_INT_H
