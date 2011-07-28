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
  void PrintStack() {
    PrintStack(this->trace, this->size);
  }
  void CopyTo(uintptr_t *dst, size_t dst_size) {
    for (size_t i = 0; i < size && i < dst_size; i++)
      dst[i] = trace[i];
    for (size_t i = size; i < dst_size; i++)
      dst[i] = 0;
  }

  void CopyFrom(uintptr_t *src, size_t src_size) {
    size = src_size;
    if (size > kStackTraceMax) size = kStackTraceMax;
    for (size_t i = 0; i < size; i++) {
      trace[i] = src[i];
    }
  }

  void FastUnwindStack(uintptr_t *frame);
  static _Unwind_Reason_Code Unwind_Trace(
      struct _Unwind_Context *ctx, void *param);
  static void PrintCurrent(uintptr_t pc = 0);

  static size_t CompressStack(AsanStackTrace *stack,
                            uint32_t *compressed, size_t size);
  static void UncompressStack(AsanStackTrace *stack,
                              uint32_t *compressed, size_t size);
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
      _Unwind_Backtrace(AsanStackTrace::Unwind_Trace, &stack);   \
    }                                                            \
    if (stack.size >= 2 && stack.trace[1] != GET_CALLER_PC()) {  \
      Printf("Stack: %d %d pc="PP" : "PP" "PP" "PP" \n",         \
             (int)fast_unwind, (int)stack.size, GET_CALLER_PC(), \
             stack.trace[0], stack.trace[1], stack.trace[2]);    \
    }                                             \
  }                                               \


#endif  // ASAN_STACK_H
