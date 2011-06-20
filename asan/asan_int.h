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
#include <stdlib.h>  // for size_t

extern "C" {
void *__asan_memalign(size_t size, size_t alignment);
void __asan_free(void *ptr);

void __asan_printf(const char *format, ...);
void __asan_check_failed(const char *cond, const char *file, int line);
}  // extern "C"

#define Printf __asan_printf

#define CHECK(cond) do { if (!(cond)) { \
  __asan_check_failed(#cond, __FILE__, __LINE__); \
}}while(0)



// The full explanation of the memory mapping could be found here:
// http://code.google.com/p/address-sanitizer/wiki/AddressSanitizerAlgorithm
const size_t kWordSize = __WORDSIZE / 8;
const size_t kWordSizeInBits = 8 * kWordSize;
const size_t kPageSizeBits = 12;
const size_t kPageSize = 1UL << kPageSizeBits;

#define MEM_TO_SHADOW(mem) (((mem) >> 3) | kCompactShadowMask)

#if __WORDSIZE == 64
const size_t kPageClusterSizeBits = 8;
const size_t kPageClusterSize = 1UL << kPageClusterSizeBits;
const size_t kPossiblePageClustersBits = 46 - kPageClusterSizeBits - kPageSizeBits;
#endif

#if __WORDSIZE == 64
  static const size_t kCompactShadowMask  = kCompactShadowMask64;
  static const size_t kHighMemEnd = 0x00007fffffffffffUL;
  #define PP "0x%016lx"
#else  // __WORDSIZE == 32
  const size_t kCompactShadowMask  = kCompactShadowMask32;
  static const size_t kHighMemEnd = 0xffffffff;
  #define PP "0x%08lx"
#endif  // __WORDSIZE


static const size_t kLowMemBeg      = 0;
static const size_t kLowMemEnd      = kCompactShadowMask - 1;

static const size_t kLowShadowBeg   = kCompactShadowMask;
static const size_t kLowShadowEnd   = MEM_TO_SHADOW(kLowMemEnd);

static const size_t kHighMemBeg     = MEM_TO_SHADOW(kHighMemEnd) + 1;

static const size_t kHighShadowBeg  = MEM_TO_SHADOW(kHighMemBeg);
static const size_t kHighShadowEnd  = MEM_TO_SHADOW(kHighMemEnd);

static const size_t kShadowGapBeg   = kLowShadowEnd + 1;
static const size_t kShadowGapEnd   = kHighShadowBeg - 1;


#endif  // ASAN_INT_H
