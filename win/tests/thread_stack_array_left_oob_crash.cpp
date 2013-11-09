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

DWORD WINAPI thread_proc(void *context) {
  int subscript = -1;
  volatile char stack_buffer[42];
  stack_buffer[subscript] = 42;

  UNREACHABLE();
// CHECK-NOT: This code should be unreachable

// CHECK: AddressSanitizer: stack-buffer-overflow on address [[ADDR:0x[0-9a-f]+]]
// CHECK: WRITE of size 1 at [[ADDR]] thread T1
// CHECK:   #0 {{.*}} thread_proc
// CHECK: Address [[ADDR]] is located in stack of thread T1 at offset {{.*}} in frame
// CHECK: thread_proc
// CHECK: Thread T1 created by T0 here:
// CHECK:   #{{[01] .*}} main
  return 0;
}

int main(void) {
  HANDLE thr = CreateThread(NULL, 0, thread_proc, NULL, 0, NULL);
  CHECK(thr > 0);
  CHECK(WAIT_OBJECT_0 == WaitForSingleObject(thr, INFINITE));
  return 0;
}
