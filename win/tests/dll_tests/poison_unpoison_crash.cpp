/* Copyright 2014 Google Inc.
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

#include "../common.h"

extern "C" {
void __asan_poison_memory_region(void const volatile*, size_t);
void __asan_unpoison_memory_region(void const volatile*, size_t);
}

void should_not_crash(volatile char *c) {
  *c = 42;
}

void should_crash(volatile char *c) {
  *c = 42;
}

DLLEXPORT int test_function() {
  char buffer[256];
  should_not_crash(&buffer[0]);
  __asan_poison_memory_region(buffer, 128);
  should_not_crash(&buffer[192]);
  __asan_unpoison_memory_region(buffer, 64);
  should_not_crash(&buffer[32]);

  should_crash(&buffer[96]);

  UNREACHABLE();
// CHECK-NOT: This code should be unreachable

// CHECK: AddressSanitizer: use-after-poison on address [[ADDR:0x[0-9a-f]+]]
// CHECK-NEXT: WRITE of size 1 at [[ADDR]] thread T0
// CHECK:      should_crash {{.*}}\poison_unpoison_crash.cpp:30
// CHECK-NEXT: test_function {{.*}}\poison_unpoison_crash.cpp:41
// CHECK-NEXT: main
// CHECK: [[ADDR]] is located in stack of thread T0 at offset {{[0-9]*}} in frame
// CHECK-NEXT: test_function {{.*}}\poison_unpoison_crash.cpp:33
  return 0;
}
