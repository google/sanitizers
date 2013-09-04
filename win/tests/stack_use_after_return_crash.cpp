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

#include <windows.h>

#include "common.h"

char *x;

void foo() {
  char stack_buffer[42];
  x = &stack_buffer[13];
}

int main(void) {
  foo();
  *x = 42;

// CHECK: AddressSanitizer: stack-use-after-return
// CHECK: WRITE of size 1 at {{.*}} thread T0
// CHECK-NEXT: main
// CHECK: is located in stack of thread T0
// CHECK-NEXT: foo
// CHECK: 'stack_buffer' {{.*}} is inside this variable

  UNREACHABLE();
// CHECK-NOT: This code should be unreachable
  return 0;
}
