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

#include "asan_int.h"
#include "asan_lock.h"
#include "asan_stack.h"

class AsanThread {
 public:
  AsanThread(AsanThread *parent, void *(*start_routine) (void *),
             void *arg, AsanStackTrace *stack,
             void (*delete_func)(void*));

  void *ThreadStart();

  AsanThread *Ref() {
    AtomicInc(&refcount_);
    return this;
  }

  void Unref() {
    CHECK(refcount_ > 0);
    if (AtomicDec(&refcount_) == 0)
      delete_func_(this);
  }

  void Announce() {
    if (tid_ == 0) return; // no need to announce the main thread.
    if (!announced_) {
      announced_ = true;
      CHECK(parent_);
      Printf("Thread T%d created by T%d here:\n", tid_, parent_->tid_);
      stack_.PrintStack();
    }
  }

  uintptr_t stack_top() { return stack_top_; }
  uintptr_t stack_bottom() { return stack_bottom_; }
  int tid() { return tid_; }

  uintptr_t AddrIsInStack(uintptr_t addr) {
    return addr >= stack_bottom_ && addr < stack_top_;
  }

  static AsanThread *FindThreadByStackAddress(uintptr_t addr) {
    ScopedLock lock(&mu_);
    AsanThread *t = live_threads_;
    do {
      if (t->AddrIsInStack(addr)) {
        return t;
      }
      t = t->next_;
    } while (t != live_threads_);
    return 0;
  }

  static AsanThread *GetCurrent();

 private:

  void SetThreadStackTopAndBottom();

  AsanThread *parent_;
  void *(*start_routine_) (void *);
  void *arg_;
  AsanStackTrace stack_;
  uintptr_t  stack_top_;
  uintptr_t  stack_bottom_;
  int        tid_;
  bool       announced_;
  int        refcount_;

  AsanThread *next_;
  AsanThread *prev_;
  void (*delete_func_)(void*);

  static AsanThread *live_threads_;
  static int n_threads_;
  static AsanLock mu_;
};

#endif  // ASAN_THREAD_H
