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

#include <vector>


static pthread_key_t g_tls_key;
// This flag is updated only once at program startup, and then read
// by concurrent threads.
static bool tls_key_created = false;

// Make it large enough so that we never run out of tids.
// I am not sure we can easily replace this with vector<>.
static const int kMaxTid = (1 << 22) + 1;
static AsanThreadSummary *thread_summaries[kMaxTid + 1];
static int n_threads;

AsanThread::AsanThread() : fake_stack_(/*empty_ctor_for_thread_0*/0) {
  CHECK(tid_ == 0);
  CHECK(this == &main_thread_);
}

AsanThread::AsanThread(int parent_tid, void *(*start_routine) (void *),
                       void *arg, AsanStackTrace *stack)
  : start_routine_(start_routine),
    arg_(arg) {
  ScopedLock lock(&mu_);
  CHECK(n_threads > 0);
  CHECK(n_threads < kMaxTid);
  int tid = n_threads;
  n_threads++;
  summary_ = new AsanThreadSummary(tid, parent_tid, stack);
  summary_->set_thread(this);
  thread_summaries[tid] = summary_;
}

AsanThreadSummary *AsanThread::FindByTid(int tid) {
  CHECK(tid >= 0);
  CHECK(tid < n_threads);
  CHECK(thread_summaries[tid]);
  return thread_summaries[tid];
}

AsanThread *AsanThread::FindThreadByStackAddress(uintptr_t addr) {
  ScopedLock lock(&mu_);
  for (int tid = 0; tid < n_threads; tid++) {
    AsanThread *t = thread_summaries[tid]->thread();
    if (!t) continue;
    if (t->FakeStack().AddrIsInFakeStack(addr)) {
      return t;
    }
    if (t->AddrIsInStack(addr)) {
      return t;
    }
  }
  return 0;
}

void *AsanThread::ThreadStart() {
  SetThreadStackTopAndBottom();
  fake_stack_.Init(stack_size());
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

  if (!start_routine_) {
    CHECK(tid_ == 0);
    return 0;
  }

  void *res = start_routine_(arg_);
  malloc_storage().CommitBack();

  if (__asan_flag_v == 1) {
    Printf("T%d exited\n", tid_);
  }

  FakeStack().Cleanup();
  return res;
}

const char *AsanThread::GetFrameNameByAddr(uintptr_t addr) {
  uintptr_t bottom = 0;
  if (AddrIsInStack(addr)) {
    bottom = stack_bottom();
  } else {
    bottom = FakeStack().AddrIsInFakeStack(addr);
    CHECK(bottom);
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

AsanThread::~AsanThread() {
  summary_->set_thread(0);
}

static void DestroyAsanTsd(void *tsd) {
  AsanThread *t = (AsanThread*)tsd;
  if (t != AsanThread::GetMain())
    delete t;
}

void AsanThread::Init() {
  CHECK(0 == pthread_key_create(&g_tls_key, DestroyAsanTsd));
  tls_key_created = true;
  SetCurrent(&main_thread_);
  main_thread_.summary_ = &main_thread_summary_;
  main_thread_summary_.set_thread(&main_thread_);
  thread_summaries[0] = &main_thread_summary_;
  n_threads = 1;
}

AsanThread* AsanThread::GetCurrent() {
  CHECK(tls_key_created);
  AsanThread *thread = (AsanThread*)pthread_getspecific(g_tls_key);
  return thread;
}

void AsanThread::SetCurrent(AsanThread *t) {
  CHECK(0 == pthread_setspecific(g_tls_key, t));
  CHECK(pthread_getspecific(g_tls_key) == t);
}

int AsanThread::n_threads_;
AsanLock AsanThread::mu_;
bool AsanThread::inited_;
AsanThread AsanThread::main_thread_;
AsanThreadSummary AsanThread::main_thread_summary_;
