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

// For each thread we create a fake stack and place stack objects on this fake
// stack instead of the real stack. The fake stack is not really a stack but
// a ring buffer so that when a function exits the fake stack is not poped
// but remains there for quite some time until the ring buffer cycles back.
// So, we poison the objects on the fake stack when function returns.
// It helps us find use-after-return bugs.
class AsanFakeStack {
 public:
  AsanFakeStack() : size_(0), pos_(0), buffer_(0) { }
  void Init(size_t size);
  void Cleanup();
  uintptr_t GetChunk(size_t chunk_size, const char *frame);
  bool AddrIsInFakeStack(uintptr_t addr) {
    return addr >= (uintptr_t)buffer_ && addr < (uintptr_t)(buffer_ + size_);
  }
  const char *GetFrameNameByAddr(uintptr_t addr);
 private:
  size_t size_;
  size_t pos_;
  char *buffer_;
};

class AsanThread {
 public:
  AsanThread();  // for T0.
  AsanThread(AsanThread *parent, void *(*start_routine) (void *),
             void *arg, AsanStackTrace *stack);

  void *ThreadStart();

  static AsanThread *FindByTid(int tid);

  AsanThread *Ref() {
    AtomicInc(&refcount_);
    return this;
  }

  void Unref();

  void Announce() {
    if (tid_ == 0) return;  // no need to announce the main thread.
    if (!announced_) {
      announced_ = true;
      CHECK(parent_);
      Printf("Thread T%d created by T%d here:\n", tid_, parent_->tid_);
      stack_.PrintStack();
    }
  }

  uintptr_t stack_top() { return stack_top_; }
  uintptr_t stack_bottom() { return stack_bottom_; }
  size_t stack_size() { return stack_top_ - stack_bottom_; }
  int tid() { return tid_; }

  AsanFakeStack &FakeStack() { return fake_stack_; }

  uintptr_t AddrIsInStack(uintptr_t addr) {
    return addr >= stack_bottom_ && addr < stack_top_;
  }

  static AsanThread *FindThreadByStackAddress(uintptr_t addr) {
    ScopedLock lock(&mu_);
    AsanThread *t = live_threads_;
    do {
      if (t->FakeStack().AddrIsInFakeStack(addr)) {
        return t;
      }
      t = t->next_;
    } while (t != live_threads_);
    return 0;
  }

  static AsanThread *GetCurrent();
  static void SetCurrent(AsanThread *t);

  static AsanThread *GetMain() { return &main_thread_; }
  static void Init();

  AsanThreadLocalMallocStorage &malloc_storage() { return malloc_storage_; }

  static const int kInvalidTid = -1;

 private:

  void SetThreadStackTopAndBottom();

  AsanThread *parent_;
  void *(*start_routine_) (void *param);
  void *arg_;
  AsanStackTrace stack_;
  uintptr_t  stack_top_;
  uintptr_t  stack_bottom_;
  int        tid_;
  bool       announced_;
  int        refcount_;

  AsanThreadLocalMallocStorage malloc_storage_;

  AsanFakeStack fake_stack_;

  AsanThread *next_;
  AsanThread *prev_;

  static AsanThread *live_threads_;
  static AsanThread main_thread_;
  static int n_threads_;
  static AsanLock mu_;
  static bool inited_;
};

#endif  // ASAN_THREAD_H
