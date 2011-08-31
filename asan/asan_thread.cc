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

#include "asan_allocator.h"
#include "asan_thread.h"
#include "asan_mapping.h"

#include <sys/mman.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>


#ifdef __APPLE__
static pthread_key_t g_tls_key;
// This flag is updated only once at program startup, and then read
// by concurrent threads.
static bool tls_key_created = false;
#else
static __thread AsanThread *tl_current_thread;
#endif

static const int kMaxTid = (1 << 16) - 1;

static AsanThread *threads[kMaxTid + 1];

AsanThread::AsanThread() {
  CHECK(tid_ == 0);
  CHECK(this == &main_thread_);
  CHECK(threads[0] == 0);
  threads[0] = &main_thread_;
}

AsanThread::AsanThread(AsanThread *parent, void *(*start_routine) (void *),
                       void *arg, AsanStackTrace *stack)
  : parent_(parent),
  start_routine_(start_routine),
  arg_(arg),
  tid_(AtomicInc(&n_threads_)),
  announced_(false),
  refcount_(1) {
  if (stack) {
    stack_ = *stack;
  }
  CHECK(tid_ <= kMaxTid);
  threads[tid_] = this;
}

AsanThread *AsanThread::FindByTid(int tid) {
  CHECK(tid >= 0);
  CHECK(tid <= kMaxTid);
  AsanThread *res = threads[tid];
  CHECK(res);
  CHECK(res->tid_ == tid);
  return res;
}

void *AsanThread::ThreadStart() {
  SetThreadStackTopAndBottom();
  fake_stack_.Init(stack_size() * 4);
  if (__asan_flag_v == 1) {
    int local = 0;
    Printf("T%d: stack ["PP","PP") size 0x%lx; local="PP"\n",
            tid_, stack_bottom_, stack_top_,
            stack_top_ - stack_bottom_, &local);
  }
  CHECK(AddrIsInMem(stack_bottom_));
  CHECK(AddrIsInMem(stack_top_));

  // clear the shadow state for the entire stack.
  uintptr_t shadow_bot = MemToShadow(stack_bottom_);
  uintptr_t shadow_top = MemToShadow(stack_top_);
  memset((void*)shadow_bot, 0, shadow_top - shadow_bot);

  CHECK(live_threads_);

  { // Insert this thread into live_threads_
    ScopedLock lock(&mu_);
    this->next_ = live_threads_;
    this->prev_ = live_threads_->prev_;
    this->prev_->next_ = this;
    this->next_->prev_ = this;
  }

  if (!start_routine_) return 0;

  void *res = start_routine_(arg_);
  malloc_storage().CommitBack();

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
  FakeStack().Cleanup();
  Unref();
  return res;
}

const char *AsanThread::GetFrameNameByAddr(uintptr_t addr) {
  uintptr_t bottom = 0;
  if (AddrIsInStack(addr)) {
    bottom = stack_bottom();
  } else {
    CHECK(FakeStack().AddrIsInFakeStack(addr));
    bottom = FakeStack().Bottom();
  }
  addr &= ~(__WORDSIZE/8 - 1);  // allign addr.
  uintptr_t *ptr = (uintptr_t*)addr;
  while (ptr >= (uintptr_t*)bottom) {
    if (ptr[0] == kFrameNameMagic)
      return (const char*)ptr[1];
    ptr--;
  }
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
  // When running under the GNU make command, pthread_attr_getstack
  // returns garbage for a stacksize.
  if (stacksize > kMaxThreadStackSize) {
    Printf("WARNING: pthread_attr_getstack returned "PP" as stacksize\n",
           stacksize);
    stack_bottom_ = stack_top_ - kMaxThreadStackSize;
  }
  CHECK(AddrIsInStack((uintptr_t)&attr));
#endif
}

void AsanThread::Init() {
#ifdef __APPLE__
    CHECK(0 == pthread_key_create(&g_tls_key, 0));
    tls_key_created = true;
#endif
  live_threads_ = GetMain();
  live_threads_->next_ = live_threads_->prev_ = live_threads_;
  SetCurrent(GetMain());
}

void AsanThread::Unref() {
  CHECK(refcount_ > 0);
  if (AtomicDec(&refcount_) == 0) {
    CHECK(tid() > 0);
    AsanStackTrace stack;
    stack.size = 0;
    __asan_free(this, &stack);
  }
}

AsanThread* AsanThread::GetCurrent() {
#ifdef __APPLE__
  CHECK(tls_key_created);
  AsanThread *thread = (AsanThread*)pthread_getspecific(g_tls_key);
  // After the thread calls _pthread_exit() the TSD is unavailable
  // and pthread_getspecific() may return NULL.
  // In this case we use the global freelist
  // for further allocations (originating from the guts of libpthread).
  return thread;
#else
  return tl_current_thread;
#endif
}

void AsanThread::SetCurrent(AsanThread *t) {
#ifdef __APPLE__
  CHECK(0 == pthread_setspecific(g_tls_key, t));
  CHECK(pthread_getspecific(g_tls_key) == t);
#else
  tl_current_thread = t;
#endif
}

int AsanThread::n_threads_;
AsanThread *AsanThread::live_threads_;
AsanLock AsanThread::mu_;
bool AsanThread::inited_;
AsanThread AsanThread::main_thread_;
