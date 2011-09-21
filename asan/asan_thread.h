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
#ifndef ASAN_THREAD_H
#define ASAN_THREAD_H

#include "asan_allocator.h"
#include "asan_int.h"
#include "asan_lock.h"
#include "asan_stack.h"

const size_t kMaxThreadStackSize = 16 * (1 << 20);  // 16M
static const uintptr_t kFrameNameMagic = 0x41B58AB3;

class AsanThread;

// These objects are created for every thread and are never deleted,
// so we can find them by tid even if the thread is long dead.
class AsanThreadSummary {
 public:
  AsanThreadSummary() { }  // for T0.
  AsanThreadSummary(int tid, int parent_tid, AsanStackTrace *stack)
    : tid_(tid),
      parent_tid_(parent_tid),
      announced_(false) {
    if (stack) {
      stack_ = *stack;
    }
    thread_ = 0;
  }
  void Announce() {
    if (tid_ == 0) return;  // no need to announce the main thread.
    if (!announced_) {
      announced_ = true;
      Printf("Thread T%d created by T%d here:\n", tid_, parent_tid_);
      stack_.PrintStack();
    }
  }
  int tid() { return tid_; }
  AsanThread *thread() { return thread_; }
  void set_thread(AsanThread *thread) { thread_ = thread; }
 private:
  int tid_;
  int parent_tid_;
  bool announced_;
  AsanStackTrace stack_;
  AsanThread *thread_;
};

// AsanThread are stored in TSD and destroyed when the thread dies.
class AsanThread {
 public:
  AsanThread();  // for T0.
  AsanThread(int parent_tid, void *(*start_routine) (void *),
             void *arg, AsanStackTrace *stack);
  ~AsanThread();

  void *ThreadStart();

  static AsanThreadSummary *FindByTid(int tid);
  static AsanThread *FindThreadByStackAddress(uintptr_t addr);

  uintptr_t stack_top() { return stack_top_; }
  uintptr_t stack_bottom() { return stack_bottom_; }
  size_t stack_size() { return stack_top_ - stack_bottom_; }
  int tid() { return summary_->tid(); }
  AsanThreadSummary *summary() { return summary_; }

  const char *GetFrameNameByAddr(uintptr_t addr, uintptr_t *offset);

  AsanFakeStack &FakeStack() { return fake_stack_; }

  uintptr_t AddrIsInStack(uintptr_t addr) {
    return addr >= stack_bottom_ && addr < stack_top_;
  }

  // Get the current thread. May return NULL.
  static AsanThread *GetCurrent();
  static void SetCurrent(AsanThread *t);

  static AsanThread *GetMain() { return &main_thread_; }
  static void Init();

  AsanThreadLocalMallocStorage &malloc_storage() { return malloc_storage_; }

  static const int kInvalidTid = -1;

 private:

  void SetThreadStackTopAndBottom();
  AsanThreadSummary *summary_;
  void *(*start_routine_) (void *param);
  void *arg_;
  uintptr_t  stack_top_;
  uintptr_t  stack_bottom_;
  int        tid_;
  bool       announced_;

  AsanThreadLocalMallocStorage malloc_storage_;

  AsanFakeStack fake_stack_;

  static AsanThread main_thread_;
  static AsanThreadSummary main_thread_summary_;
  static int n_threads_;
  static AsanLock mu_;
  static bool inited_;
};

#endif  // ASAN_THREAD_H
