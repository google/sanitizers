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

#ifndef ASAN_RTL_H
#define ASAN_RTL_H

const unsigned long long kCompactShadowMask64 = 1ULL << 44;
const unsigned long      kCompactShadowMask32 = 1UL << 29;

// We create poisoned rezones of 32 *bytes* around stack objects and globals.
// We can poison the entire redzone with one 4-byte store.
// For objects with ((size % 32) != 0) we create left redzone of 32 bytes
// and right redzone of 32+(32-(size%32)) bytes.
// The size of the heap redzone is different and is not a constant.
const unsigned kAsanRedzone = 32;

// These magic numbers represent the poison values for partial 32-byte redzones.
// kPartialRedzonePoisonValues[i] (i = 1..31) is the value with which we should
// poison a partial redzone at the right of a stack/global object of size i.
const unsigned kPartialRedzonePoisonValues [32] = {
  0x00000000, 0xa3a2a101, 0xa3a2a102, 0xa3a2a103,  // 0 - 3
  0xa3a2a104, 0xa3a2a105, 0xa3a2a106, 0xa3a2a107,  // 4 - 7

  0xa3a2a100, 0xa3a20100, 0xa3a20200, 0xa3a20300,  // 8 - 11
  0xa3a20400, 0xa3a20500, 0xa3a20600, 0xa3a20700,  // 12 - 15

  0xa3a20000, 0xa3010000, 0xa3020000, 0xa3030000,  // 16 - 19
  0xa3040000, 0xa3050000, 0xa3060000, 0xa3070000,  // 20 - 23

  0xa3000000, 0x01000000, 0x02000000, 0x03000000,  // 24 - 27
  0x04000000, 0x05000000, 0x06000000, 0x07000000,  // 28 - 31
};

#endif  // ASAN_RTL_H
