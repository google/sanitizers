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

  void FastUnwindStack(uintptr_t pc, uintptr_t bp);
  static _Unwind_Reason_Code Unwind_Trace(
      struct _Unwind_Context *ctx, void *param);
  static uintptr_t GetCurrentPc();

  static size_t CompressStack(AsanStackTrace *stack,
                            uint32_t *compressed, size_t size);
  static void UncompressStack(AsanStackTrace *stack,
                              uint32_t *compressed, size_t size);
};

// Get the stack trace with the given pc and bp.
// The pc will be in the position 0 of the resulting stack trace.
// The bp may refer to the current frame or to the caller's frame.
// With fast_unwind==true we unwind using frame pointers.
// Otherwise we use _Unwind_Backtrace.
#define GET_STACK_TRACE_WITH_PC_AND_BP(max_s, fast_unwind, pc, bp)  \
  AsanStackTrace stack;                             \
  {                                                 \
    uintptr_t saved_pc = pc;                        \
    uintptr_t saved_bp = bp;                        \
    stack.size = 0;                                 \
    stack.trace[0] = saved_pc;                      \
    if ((max_s) > 1) {                              \
      stack.max_size = max_s;                       \
      if (fast_unwind) {                            \
        stack.FastUnwindStack(saved_pc, saved_bp);  \
      } else {                                      \
        _Unwind_Backtrace(AsanStackTrace::Unwind_Trace, &stack);   \
        if (stack.size == 0)                        \
          stack.FastUnwindStack(saved_pc, saved_bp);\
      }                                             \
    }                                               \
  }                                                 \

#define GET_STACK_TRACE_HERE(max_size, fast_unwind)         \
  GET_STACK_TRACE_WITH_PC_AND_BP(max_size, fast_unwind,     \
     AsanStackTrace::GetCurrentPc(), GET_CURRENT_FRAME())   \

#define PRINT_CURRENT_STACK()                    \
  {                                              \
    GET_STACK_TRACE_HERE(kStackTraceMax, false); \
    stack.PrintStack();                          \
  }                                              \


#endif  // ASAN_STACK_H
