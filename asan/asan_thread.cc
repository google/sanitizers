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

#include "asan_thread.h"
#include "asan_mapping.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

AsanThread::AsanThread(AsanThread *parent, void *(*start_routine) (void *),
                       void *arg, AsanStackTrace *stack,
                       void (*delete_func)(void*))
  : parent_(parent),
  start_routine_(start_routine),
  arg_(arg),
  tid_(AtomicInc(&n_threads_) - 1),
  announced_(false),
  refcount_(1),
  delete_func_(delete_func) {
  if (stack) {
    stack_ = *stack;
  }
  if (tid_ == 0) {
    live_threads_ = next_ = prev_ = this;
  }
}

void *AsanThread::ThreadStart() {
  SetThreadStackTopAndBottom();
  if (__asan_flag_v == 1) {
    int local = 0;
    Printf ("T%d: stack ["PP","PP") size 0x%lx; local="PP"\n",
            tid_, stack_bottom_, stack_top_, stack_top_ - stack_bottom_, &local);
  }
  CHECK(AddrIsInMem(stack_bottom_));
  CHECK(AddrIsInMem(stack_top_));

  // clear the shadow state for the entire stack.
  uintptr_t shadow_bot = MemToShadow(stack_bottom_);
  uintptr_t shadow_top = MemToShadow(stack_top_);
  memset((void*)shadow_bot, 0, shadow_top - shadow_bot);

  { // Insert this thread into live_threads_
    ScopedLock lock(&mu_);
    this->next_ = live_threads_;
    this->prev_ = live_threads_->prev_;
    this->prev_->next_ = this;
    this->next_->prev_ = this;
  }

  if (!start_routine_) return 0;

  void *res = start_routine_(arg_);

  if (__asan_flag_v == 1) {
    Printf("T%d exited\n", tid_);
  }

  { // Remove this from live_threads_
    ScopedLock lock(&mu_);
    AsanThread *prev = this->prev_;
    AsanThread *next = this->next_;
    prev->next_ = next_;
    next->prev_ = prev_;
  }
  Unref();
  return res;
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
  __asan_need_real_malloc = true;
  pthread_attr_t attr;
  CHECK (pthread_getattr_np(pthread_self(), &attr) == 0);
  size_t stacksize = 0;
  void *stackaddr = NULL;
  pthread_attr_getstack(&attr, &stackaddr, &stacksize);
  pthread_attr_destroy(&attr);
  __asan_need_real_malloc = false;

  const size_t kMaxStackSize = 16 * (1 << 20);  // 16M
  stack_top_ = (uintptr_t)stackaddr + stacksize;
  stack_bottom_ = (uintptr_t)stackaddr;
  // When running under the GNU make command, pthread_attr_getstack
  // returns garbage for a stacksize.
  if (stacksize > kMaxStackSize) {
    Printf("WARNING: pthread_attr_getstack returned "PP" as stacksize\n",
           stacksize);
    stack_bottom_ = stack_top_ - kMaxStackSize;
  }
  CHECK(AddrIsInStack((uintptr_t)&attr));
#endif
}


int AsanThread::n_threads_;
AsanThread *AsanThread::live_threads_;
