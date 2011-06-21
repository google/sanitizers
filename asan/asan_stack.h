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
#include "unwind.h"

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
  void FastUnwindStack(uintptr_t *frame);
  static _Unwind_Reason_Code Unwind_Trace(
      struct _Unwind_Context *ctx, void *param);
};

#define GET_STACK_TRACE_HERE(max_s, fast_unwind)  \
  AsanStackTrace stack;                           \
  if ((max_s) <= 1) {                             \
    stack.size = 1;                               \
    stack.trace[0] = GET_CALLER_PC();             \
  } else {                                        \
    stack.max_size = max_s;                       \
    stack.size = 0;                               \
    if (fast_unwind) {   \
      stack.FastUnwindStack(GET_CURRENT_FRAME()); \
    } else {                                      \
      _Unwind_Backtrace(AsanStackTrace::Unwind_Trace, &stack);      \
    }                                             \
    if (stack.size >= 2 && stack.trace[1] != GET_CALLER_PC()) {   \
      Printf("Stack: %d %d pc="PP" : "PP" "PP" "PP" \n", \
             (int)fast_unwind, (int)stack.size, GET_CALLER_PC(), \
             stack.trace[0], stack.trace[1], stack.trace[2]);                          \
    }                                             \
  }                                               \


#endif  // ASAN_STACK_H
