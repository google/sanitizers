/* Copyright 2012 Google Inc.
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

#include "common.h"

int main(void) {
  volatile char *buffer = (char*)realloc(NULL, 42);
  buffer[42] = 42;

  UNREACHABLE();
// CHECK-NOT: This code should be unreachable

// CHECK: AddressSanitizer heap-buffer-overflow on address [[ADDR:0x[0-9a-f]+]]
// CHECK: WRITE of size 1 at [[ADDR]] thread T0
// CHECK:   #0 {{.*}} main
// CHECK: [[ADDR]] is located 0 bytes to the right of 42-byte region
// CHECK: allocated by thread T0 here:
// CHECK:   #0 {{.*}} realloc
  free_noopt(buffer);
  return 0;
}
