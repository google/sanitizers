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
  static const char *foo = "foobarspam";
  if (foo[16])
    printf("Boo\n");

  UNREACHABLE();
// CHECK-NOT: Boo
// CHECK-NOT: This code should be unreachable

// CHECK: AddressSanitizer: global-buffer-overflow on address [[ADDR:0x[0-9a-f]+]]
// CHECK: READ of size 1 at [[ADDR]] thread T0
// CHECK:   #0 {{.*}} main
// CHECK: [[ADDR]] is located 5 bytes to the right of global variable {{.*}} of size 11
  return 0;
}
