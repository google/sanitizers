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

char *other_thread_stack_object = NULL;

DWORD WINAPI thread_proc(void *context) {
  char stack_buffer[42];
  other_thread_stack_object = &stack_buffer[13];
  // TODO: Do we need an extra test for ExitThread(0); ?
  return 0;
}

int main(void) {
  DWORD tid = -1;
  HANDLE thr = CreateThread(NULL, 0, thread_proc, NULL, 0, &tid);
  CHECK(thr > 0);
  CHECK(WAIT_OBJECT_0 == WaitForSingleObject(thr, INFINITE));
  CHECK(other_thread_stack_object != NULL);

  // TODO: ASan doesn't generate a crash stack here at the momoent.
  *other_thread_stack_object = 42;
  return 0;
}
