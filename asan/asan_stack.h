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

#ifndef ASAN_STACK_H
#define ASAN_STACK_H

#include "asan_int.h"

static const size_t kStackTraceMax = 64;

struct AsanStackTrace {
  size_t size;
  size_t max_size;
  uintptr_t trace[kStackTraceMax];
  static void PrintStack(uintptr_t *addr, size_t size);
  static void Init();
  void PrintStack() {
    PrintStack(this->trace, this->size);
  }
};

#endif  // ASAN_STACK_H
