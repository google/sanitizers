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

DWORD WINAPI thread_proc_1(void *context) {
  int cnt1, cnt2, cnt3;
  cnt1 = 1;
  cnt2 = 2;
  cnt3 = 3;
  return 0;
}

DWORD WINAPI thread_proc_2(void *context) {
  char stack_buffer[42];
  for (int i = 0; i < sizeof(stack_buffer); ++i)
    stack_buffer[i] = 42;
  return 0;
}

int main(void) {
  DWORD tid = -1;
  HANDLE thr = NULL;

  thr = CreateThread(NULL, 0, thread_proc_1, NULL, 0, &tid);
  CHECK(thr > 0);
  CHECK(WAIT_OBJECT_0 == WaitForSingleObject(thr, INFINITE));

  thr = CreateThread(NULL, 0, thread_proc_2, NULL, 0, &tid);
  CHECK(thr > 0);
  CHECK(WAIT_OBJECT_0 == WaitForSingleObject(thr, INFINITE));
  return 0;
}
