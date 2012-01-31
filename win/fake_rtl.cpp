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

#include <windows.h>

#include <assert.h>
#include <stdio.h>

extern "C" {
#include "fake_rtl.h"
}

#define CHECK(x) assert(x)

const size_t SHADOW_START  = 512 * 1024 * 1024,
             SHADOW_SIZE   = 512 * 1024 * 1024,
             SHADOW_SHIFT  = 3;

const size_t MemToShadow(size_t x) {
  return SHADOW_START + (x >> SHADOW_SHIFT);
}

const size_t RESTRICT_LOW  = MemToShadow(SHADOW_START),
             RESTRICT_HIGH = MemToShadow(SHADOW_START + SHADOW_SIZE);

extern "C" int __asan_init() {
  static void * shadow_at;
  if (shadow_at == NULL) {
    if (RESTRICT_LOW != 0) {
      // Reserve the whole shadow.
      shadow_at = VirtualAlloc(
          (void*)SHADOW_START, SHADOW_SIZE,
          MEM_RESERVE, PAGE_READWRITE);
      assert((size_t)shadow_at == SHADOW_START);

      void *allocated;

      // Commit the low-shadow.
      allocated = VirtualAlloc(
          (void*)SHADOW_START, RESTRICT_LOW - SHADOW_START,
          MEM_COMMIT, PAGE_READWRITE);
      assert((size_t)allocated == SHADOW_START);

      // Commit the high-shadow.
      allocated = VirtualAlloc(
          (void*)RESTRICT_HIGH, SHADOW_START + SHADOW_SIZE - RESTRICT_HIGH,
          MEM_COMMIT, PAGE_READWRITE);
      assert((size_t)allocated == RESTRICT_HIGH);

      // Restrict the RESTRICT region.
      allocated = VirtualAlloc(
          (void*)RESTRICT_LOW, RESTRICT_HIGH - RESTRICT_LOW,
          MEM_COMMIT, PAGE_NOACCESS);
      assert((size_t)allocated == RESTRICT_LOW);
    } else {
      // Only commit the high-shadow as there's no low-shadow.
      // TODO(timurrrr): should we PAGE_NOACCESS the RESTRICT_ section? How?
      shadow_at = VirtualAlloc(
          (void*)RESTRICT_HIGH, SHADOW_SIZE - RESTRICT_HIGH,
          MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
      assert((size_t)shadow_at == RESTRICT_HIGH);
    }

    printf("Successfully allocated the shadow memory!\n");
  }
  return true;
}

static int __asan_is_sane = __asan_init();

extern "C" void __asan_report_store4(void *ptr) {
  printf("Error: write size 4 @0x%p\n", ptr);
}

extern "C" void __asan_report_load4(void *ptr) {
  printf("Error: read size 4 @0x%p\n", ptr);
}

extern "C" void __asan_register_globals(void *globals, size_t n) {
  printf("__asan_register_globals is a fake\n");
}

extern "C" void __asan_unregister_globals(void *globals, size_t n) {
  printf("__asan_unregister_globals is a fake\n");
}

void * __asan_malloc(size_t size) {
  printf("__asan_malloc(size=%d) called\n", size);
  return NULL;
}
