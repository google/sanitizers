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

#include <stdint.h>  // for __WORDSIZE
#include <stdlib.h>  // for size_t

class AsanThread;
class AsanStackTrace;


extern "C" {
void __asan_init() __attribute__((visibility("default")));
void __asan_printf(const char *format, ...);
void __asan_check_failed(const char *cond, const char *file, int line);
void *__asan_mmap(void *addr, size_t length, int prot, int flags,
                                    int fd, uint64_t offset);

}  // extern "C"

extern size_t __asan_flag_quarantine_size;
extern int    __asan_flag_demangle;
extern bool   __asan_flag_symbolize;
extern int    __asan_flag_v;
extern bool   __asan_flag_mt;
extern size_t __asan_flag_redzone;
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

#define ASAN_ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))

const size_t kWordSize = __WORDSIZE / 8;
const size_t kWordSizeInBits = 8 * kWordSize;
const size_t kPageSizeBits = 12;
const size_t kPageSize = 1UL << kPageSizeBits;

#define GET_CALLER_PC() (uintptr_t)__builtin_return_address(0)
#define GET_CURRENT_FRAME() (uintptr_t*)__builtin_frame_address(0)

// Poison the shadow memory which corresponds to 'redzone_size' bytes
// of the original memory, where first 'size' bytes are addressable.
static inline void
PoisonShadowPartialRightRedzone(unsigned char *shadow,
                                uintptr_t size,
                                uintptr_t redzone_size,
                                uintptr_t shadow_granularity,
                                unsigned char magic) {
  for (uintptr_t i = 0; i < redzone_size;
       i+= shadow_granularity, shadow++) {
    if (i + shadow_granularity <= size) {
      *shadow = 0;  // fully addressable
    } else if (i >= size) {
      *shadow = (shadow_granularity == 128) ? 0xff : magic;  // unaddressable
    } else {
      *shadow = size - i;  // first size-i bytes are addressable
    }
  }
}


// -------------------------- Atomic ---------------- {{{1
template <class T>
static inline T AtomicInc(T *a) {
  if (!__asan_flag_mt) return ++(*a);
  return __sync_add_and_fetch(a, 1);
}

template <class T>
static inline T AtomicDec(T *a) {
  if (!__asan_flag_mt) return --(*a);
  return __sync_add_and_fetch(a, -1);
}



#endif  // ASAN_INT_H
