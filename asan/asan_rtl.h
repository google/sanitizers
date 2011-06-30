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

const unsigned long kShadowScale = 3;
// One byte of shadow corresponds to so many aligned bytes of app memory.
const unsigned long kShadowGranularity = 1UL << kShadowScale;
const unsigned long long kCompactShadowMask64 = 1ULL << 44;
const unsigned long      kCompactShadowMask32 = 1UL << 29;

// We create poisoned rezones of 32 *bytes* around stack objects and globals.
// We can poison the entire redzone with one 4-byte store.
// For objects with ((size % 32) != 0) we create left redzone of 32 bytes
// and right redzone of 32+(32-(size%32)) bytes.
// The size of the heap redzone is different and is not a constant.
const unsigned kAsanRedzone = 32;

// Poison the shadow memory which corresponds to 'redzone_size' bytes
// of the original memory, where first 'size' bytes are addressable.
static inline void
PoisonShadowPartialRightRedzone(unsigned char *shadow,
                                unsigned long size,
                                unsigned long redzone_size,
                                unsigned long shadow_granularity,
                                unsigned char magic) {
  for (unsigned long i = 0; i < redzone_size;
       i+= shadow_granularity, shadow++) {
    if (i + shadow_granularity <= size) {
      *shadow = 0;  // fully addressable
    } else if (i >= size) {
      *shadow = shadow_granularity == 128 ? 0xff : magic;  // unaddressable
    } else {
      *shadow = size - i;  // first size-i bytes are addressable
    }
  }
}

#endif  // ASAN_RTL_H
