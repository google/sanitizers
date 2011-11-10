//===-- asan_mac.cc -----------------------------------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file is a part of AddressSanitizer, an address sanity checker.
//
// Mac-specific details.
//===----------------------------------------------------------------------===//

#ifndef __APPLE__
#error "This file should be used on Mac OS X only."
#endif

#include "asan_mac.h"

#include "asan_internal.h"
#include "asan_stack.h"
#include "asan_thread.h"
#include "asan_thread_registry.h"

#include <algorithm>

#include <sys/mman.h>
#include <unistd.h>

namespace __asan {

extern dispatch_async_f_f real_dispatch_async_f;

// No-op. Mac does not support static linkage anyway.
void *AsanDoesNotSupportStaticLinkage() {
  return NULL;
}

void *asan_mmap(void *addr, size_t length, int prot, int flags,
                                    int fd, uint64_t offset) {
  return mmap(addr, length, prot, flags, fd, offset);
}

ssize_t asan_write(int fd, const void *buf, size_t count) {
  return write(fd, buf, count);
}

// Support for dispatch_async_f and dispatch_async (which uses
// dispatch_async_f) from libdispatch on Mac OS.
// TODO(glider): libdispatch API contains other functions that we don't support
// yet.
//
// I (glider) was referring to
// git://github.com/DrPizza/libdispatch.git/libdispatch/src/queue.c
// while making this change.
// The reference manual for Grand Central Dispatch is available at
// http://developer.apple.com/library/mac/#documentation/Performance/Reference/GCD_libdispatch_Ref/Reference/reference.html

extern "C"
void asan_dispatch_call_block_and_release(void *block) {
  GET_STACK_TRACE_HERE(kStackTraceMax, /*fast_unwind*/false);
  asan_block_context_t *context = (asan_block_context_t*)block;

  AsanThread *t = asanThreadRegistry().GetCurrent();
  if (t) {
    // We've already executed a job on this worker thread. Let's reuse the
    // AsanThread object.
    CHECK(t != asanThreadRegistry().GetMain());
    // Flush the statistics and update the current thread's tid.
    asanThreadRegistry().UnregisterThread(t);
    asanThreadRegistry().RegisterThread(t, context->parent_tid, &stack);
  } else {
    t = (AsanThread*)asan_malloc(sizeof(AsanThread), &stack);
    new(t) AsanThread(context->parent_tid,
                      /*start_routine*/NULL, /*arg*/NULL, &stack);
    asanThreadRegistry().SetCurrent(t);
  }
  // Call the original dispatcher for the block.
  context->func(context->block);
  asan_free(context, &stack);
}

}  // namespace __asan

using namespace __asan;  // NOLINT

extern "C"
int WRAP(dispatch_async_f)(dispatch_queue_t dq,
                           void *ctxt,
                           dispatch_function_t func) {
  GET_STACK_TRACE_HERE(kStackTraceMax, /*fast_unwind*/false);
  asan_block_context_t *asan_ctxt =
      (asan_block_context_t*) asan_malloc(sizeof(asan_block_context_t), &stack);
  asan_ctxt->block = ctxt;
  asan_ctxt->func = func;
  AsanThread *curr_thread = asanThreadRegistry().GetCurrent();
  CHECK(curr_thread);
  asan_ctxt->parent_tid = curr_thread->tid();
  return real_dispatch_async_f(dq, (void*)asan_ctxt,
                               asan_dispatch_call_block_and_release);
}
