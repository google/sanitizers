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

DLLEXPORT int test_function() {
  volatile char *buffer = (char*)malloc(42);
  free_noopt(buffer);
  buffer[0] = 42;

  UNREACHABLE();
// CHECK-NOT: This code should be unreachable

// CHECK: AddressSanitizer: heap-use-after-free on address [[ADDR:0x[0-9a-f]+]]
// CHECK: WRITE of size 1 at [[ADDR]] thread T0
// CHECK:   test_function {{.*}}\malloc_uaf_crash.cpp:23
// CHECK:   main
// CHECK: [[ADDR]] is located 0 bytes inside of 42-byte region
// CHECK: freed by thread T0 here:
// CHECK:   free
// CHECK:   free_noopt {{.*}}\common.h:43
// CHECK:   function {{.*}}\malloc_uaf_crash.cpp:22
// CHECK:   main
// CHECK: previously allocated by thread T0 here:
// CHECK:   malloc
// CHECK:   test_function {{.*}}\malloc_uaf_crash.cpp:21
// CHECK:   main
  return 0;
}
