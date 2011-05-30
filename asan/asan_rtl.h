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
// Author: Kostya Serebryany

#ifndef ASAN_RTL_H
#define ASAN_RTL_H

#include <stdlib.h>
#include <stdint.h>

const uint64_t kFullHighShadowMask = 0x0000600000000000ULL;
const uint64_t kFullLowShadowMask = (1ULL << 42);

const uint64_t kCompactShadowMask64 = 1ULL << 44;
const size_t   kCompactShadowMask32 = 1UL << 29;

const uint8_t  kInMemoryPoison8  = 0xab;
const uint16_t kInMemoryPoison16 = 0xabab;
const uint32_t kInMemoryPoison32 = 0xabababab;
const uint64_t kInMemoryPoison64 = 0xababababababababULL;

const size_t kBankPadding = 64;

// When an illegal address is detected, we need to store it somewhere
// before causing SEGV (with compact mapping we can not exactly compute the
// actuall address given the BAD address, because the mapping is 8B-to-1B).
const size_t kOffsetToStoreEffectiveAddressInShadow = -64;

// Bits in __asan_flag
enum AsanFlag {
  AsanFlagShouldBePresent,
  AsanFlag32,
  AsanFlag64,
  AsanFlagCrOS,
  AsanFlagByteToByteShadow,
  AsanFlagByteToQwordShadow,
  AsanFlagInMemoryPoison,
  AsanFlagUseCall,
  AsanFlagUseSegv,
  AsanFlagLast
};

#endif  // ASAN_RTL_H
