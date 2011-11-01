//===-- asan_thread.cc ------------*- C++ -*-===//
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
// Thread-related code.
//===----------------------------------------------------------------------===//
#include "asan_allocator.h"
#include "asan_interceptors.h"
#include "asan_thread.h"
#include "asan_thread_registry.h"
#include "asan_mapping.h"

#include <sys/mman.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

namespace __asan {

AsanThread::AsanThread(LinkerInitialized x)
    : fake_stack_(/*empty_ctor_for_thread_0*/0),
      stats_(x) { }

AsanThread::AsanThread(int parent_tid, void *(*start_routine) (void *),
                       void *arg, AsanStackTrace *stack)
    : start_routine_(start_routine),
      arg_(arg) {
  asanThreadRegistry().RegisterThread(this, parent_tid, stack);
}

AsanThread::~AsanThread() {
  asanThreadRegistry().UnregisterThread(this);
  FakeStack().Cleanup();
}

void *AsanThread::ThreadStart() {
  SetThreadStackTopAndBottom();
  fake_stack_.Init(stack_size());
  if (FLAG_v == 1) {
    int local = 0;
    Printf("T%d: stack ["PP","PP") size 0x%lx; local="PP"\n",
            tid(), stack_bottom_, stack_top_,
            stack_top_ - stack_bottom_, &local);
  }
  CHECK(AddrIsInMem(stack_bottom_));
  CHECK(AddrIsInMem(stack_top_));

  // clear the shadow state for the entire stack.
  uintptr_t shadow_bot = MemToShadow(stack_bottom_);
  uintptr_t shadow_top = MemToShadow(stack_top_);
  real_memset((void*)shadow_bot, 0, shadow_top - shadow_bot);

  if (!start_routine_) {
    CHECK(tid() == 0);
    return 0;
  }

  void *res = start_routine_(arg_);
  malloc_storage().CommitBack();

  if (FLAG_v == 1) {
    Printf("T%d exited\n", tid());
  }

  return res;
}

const char *AsanThread::GetFrameNameByAddr(uintptr_t addr, uintptr_t *offset) {
  uintptr_t bottom = 0;
  bool is_fake_stack = false;
  if (AddrIsInStack(addr)) {
    bottom = stack_bottom();
  } else {
    bottom = FakeStack().AddrIsInFakeStack(addr);
    CHECK(bottom);
    is_fake_stack = true;
  }
  uintptr_t aligned_addr = addr & ~(__WORDSIZE/8 - 1);  // align addr.
  uintptr_t *ptr = (uintptr_t*)aligned_addr;
  while (ptr >= (uintptr_t*)bottom) {
    if (ptr[0] == kCurrentStackFrameMagic ||
        (is_fake_stack && ptr[0] == kRetiredStackFrameMagic)) {
      *offset = addr - (uintptr_t)ptr;
      return (const char*)ptr[1];
    }
    ptr--;
  }
  *offset = 0;
  return "UNKNOWN";
}

void AsanThread::SetThreadStackTopAndBottom() {
#ifdef __APPLE__
  size_t stacksize = pthread_get_stacksize_np(pthread_self());
  void *stackaddr = pthread_get_stackaddr_np(pthread_self());
  stack_top_ = (uintptr_t)stackaddr;
  stack_bottom_ = stack_top_ - stacksize;
  int local;
  CHECK(AddrIsInStack((uintptr_t)&local));
#else
  pthread_attr_t attr;
  CHECK(pthread_getattr_np(pthread_self(), &attr) == 0);
  size_t stacksize = 0;
  void *stackaddr = NULL;
  pthread_attr_getstack(&attr, &stackaddr, &stacksize);
  pthread_attr_destroy(&attr);

  stack_top_ = (uintptr_t)stackaddr + stacksize;
  stack_bottom_ = (uintptr_t)stackaddr;
  // When running with unlimited stack size, we still want to set some limit.
  // The unlimited stack size is caused by 'ulimit -s unlimited'.
  // Also, for some reason, GNU make spawns subrocesses with unlimited stack.
  if (stacksize > kMaxThreadStackSize) {
    stack_bottom_ = stack_top_ - kMaxThreadStackSize;
  }
  CHECK(AddrIsInStack((uintptr_t)&attr));
#endif
}

}  // namespace __asan
