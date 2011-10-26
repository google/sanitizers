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
#include "asan_mapping.h"

#include <sys/mman.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

static pthread_key_t g_tls_key;
// This flag is updated only once at program startup, and then read
// by concurrent threads.
static bool tls_key_created = false;

// Make it large enough so that we never run out of tids.
// I am not sure we can easily replace this with vector<>.
static const int kMaxTid = (1 << 22) + 1;
static AsanThreadSummary *thread_summaries[kMaxTid + 1];

AsanThread::AsanThread(__asan::LinkerInitialized)
    : fake_stack_(/*empty_ctor_for_thread_0*/0) {
  CHECK(this == &main_thread_);
}

AsanThread::AsanThread(int parent_tid, void *(*start_routine) (void *),
                       void *arg, AsanStackTrace *stack)
  : start_routine_(start_routine),
    arg_(arg) {
  ScopedLock lock(&mu_);
  CHECK(n_threads_ > 0);
  CHECK(n_threads_ < kMaxTid);
  int tid = n_threads_;
  n_threads_++;
  summary_ = new AsanThreadSummary(tid, parent_tid, stack);
  summary_->set_thread(this);
  thread_summaries[tid] = summary_;
}

AsanThreadSummary *AsanThread::FindByTid(int tid) {
  CHECK(tid >= 0);
  CHECK(tid < n_threads_);
  CHECK(thread_summaries[tid]);
  return thread_summaries[tid];
}

AsanThread *AsanThread::FindThreadByStackAddress(uintptr_t addr) {
  ScopedLock lock(&mu_);
  for (int tid = 0; tid < n_threads_; tid++) {
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
            tid(), stack_bottom_, stack_top_,
            stack_top_ - stack_bottom_, &local);
  }
  CHECK(AddrIsInMem(stack_bottom_));
  CHECK(AddrIsInMem(stack_top_));

  // clear the shadow state for the entire stack.
  uintptr_t shadow_bot = MemToShadow(stack_bottom_);
  uintptr_t shadow_top = MemToShadow(stack_top_);
  __asan::real_memset((void*)shadow_bot, 0, shadow_top - shadow_bot);

  if (!start_routine_) {
    CHECK(tid() == 0);
    return 0;
  }

  void *res = start_routine_(arg_);
  malloc_storage().CommitBack();

  if (__asan_flag_v == 1) {
    Printf("T%d exited\n", tid());
  }

  return res;
}

const char *AsanThread::GetFrameNameByAddr(uintptr_t addr, uintptr_t *offset) {
  uintptr_t bottom = 0;
  if (AddrIsInStack(addr)) {
    bottom = stack_bottom();
  } else {
    bottom = FakeStack().AddrIsInFakeStack(addr);
    CHECK(bottom);
  }
  uintptr_t aligned_addr = addr & ~(__WORDSIZE/8 - 1);  // align addr.
  uintptr_t *ptr = (uintptr_t*)aligned_addr;
  while (ptr >= (uintptr_t*)bottom) {
    if (ptr[0] == kFrameNameMagic) {
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

AsanThread::~AsanThread() {
  FakeStack().Cleanup();
  summary_->set_thread(0);
}

static void DestroyAsanTsd(void *tsd) {
  AsanThread *t = (AsanThread*)tsd;
  if (t != AsanThread::GetMain()) {
    delete t;
  }
}

void AsanThread::Init() {
  CHECK(0 == pthread_key_create(&g_tls_key, DestroyAsanTsd));
  tls_key_created = true;
  SetCurrent(&main_thread_);
  main_thread_.summary_ = &main_thread_summary_;
  main_thread_summary_.set_thread(&main_thread_);
  thread_summaries[0] = &main_thread_summary_;
  n_threads_ = 1;
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
AsanThread AsanThread::main_thread_(__asan::LINKER_INITIALIZED);
AsanThreadSummary AsanThread::main_thread_summary_(__asan::LINKER_INITIALIZED);
