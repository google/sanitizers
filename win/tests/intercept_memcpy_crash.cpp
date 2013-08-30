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

void call_memcpy(void* (__cdecl *f)(void *, const void *, size_t),
                 void *a, void *b, size_t c) {
  f(a, b, c);
}

int main(void) {
  char buff1[6] = "Hello", buff2[5];
  call_memcpy(&memcpy, buff2, buff1, 6);

  UNREACHABLE();
// CHECK-NOT: This code should be unreachable

// CHECK: AddressSanitizer: stack-buffer-overflow on address [[ADDR:0x[0-9a-f]+]]
// CHECK: WRITE of size 6 at [[ADDR]] thread T0
// CHECK:   wrap_memcpy
// CHECK:   call_memcpy
// CHECK:   main
// CHECK: Address [[ADDR]] is located in stack of thread T0 at offset {{.*}} in frame
// CHECK:   #0 {{.*}} main
}
