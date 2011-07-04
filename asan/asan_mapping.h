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

#ifndef ASAN_MAPPING_H
#define ASAN_MAPPING_H

#include "asan_int.h"

// The full explanation of the memory mapping could be found here:
// http://code.google.com/p/address-sanitizer/wiki/AddressSanitizerAlgorithm

extern uintptr_t __asan_mapping_scale;
extern uintptr_t __asan_mapping_offset;

#define SHADOW_SCALE __asan_mapping_scale
#define SHADOW_GRANULARITY (1ULL << SHADOW_SCALE)
#define SHADOW_OFFSET __asan_mapping_offset

#define MEM_TO_SHADOW(mem) (((mem) >> SHADOW_SCALE) | (__asan_mapping_offset))

#if __WORDSIZE == 64
const size_t kPageClusterSizeBits = 8;
const size_t kPageClusterSize = 1UL << kPageClusterSizeBits;
const size_t kPossiblePageClustersBits = 46 - kPageClusterSizeBits - kPageSizeBits;
#endif

#if __WORDSIZE == 64
  static const size_t kHighMemEnd = 0x00007fffffffffffUL;
#else  // __WORDSIZE == 32
  static const size_t kHighMemEnd = 0xffffffff;
#endif  // __WORDSIZE


#define kLowMemBeg      0
#define kLowMemEnd      (SHADOW_OFFSET - 1)

#define kLowShadowBeg   SHADOW_OFFSET
#define kLowShadowEnd   MEM_TO_SHADOW(kLowMemEnd)

#define kHighMemBeg     (MEM_TO_SHADOW(kHighMemEnd) + 1)

#define kHighShadowBeg  MEM_TO_SHADOW(kHighMemBeg)
#define kHighShadowEnd  MEM_TO_SHADOW(kHighMemEnd)

#define kShadowGapBeg   (kLowShadowEnd + 1)
#define kShadowGapEnd   (kHighShadowBeg - 1)

#define kGlobalAndStackRedzone \
      (SHADOW_GRANULARITY < 32 ? 32 : SHADOW_GRANULARITY)

static inline bool AddrIsInLowMem(uintptr_t a) {
  return a < kLowMemEnd;
}

static inline bool AddrIsInLowShadow(uintptr_t a) {
  return a >= kLowShadowBeg && a <= kLowShadowEnd;
}

static inline bool AddrIsInHighMem(uintptr_t a) {
  return a >= kHighMemBeg && a <= kHighMemEnd;
}

static inline bool AddrIsInMem(uintptr_t a) {
  return AddrIsInLowMem(a) || AddrIsInHighMem(a);
}

static inline uintptr_t MemToShadow(uintptr_t p) {
  CHECK(AddrIsInMem(p));
  return MEM_TO_SHADOW(p);
}

static inline bool AddrIsInHighShadow(uintptr_t a) {
  return a >= kHighShadowBeg && a <=  kHighMemEnd;
}

static inline bool AddrIsInShadow(uintptr_t a) {
  return AddrIsInLowShadow(a) || AddrIsInHighShadow(a);
}


#endif  // ASAN_MAPPING_H
