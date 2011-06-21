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

#ifndef ASAN_LOCK_H
#define ASAN_LOCK_H

#include "asan_int.h"

#ifdef __APPLE__
#include <libkern/OSAtomic.h>
class AsanLock {
 public:
  AsanLock() {}  // TODO(glider)
  ~AsanLock() {} // TODO(glider)
  void Lock() {
    OSSpinLockLock(&mu_);
  }
  void Unlock() {
    OSSpinLockUnlock(&mu_);
  }
 private:
  OSSpinLock mu_;
};

#else  // assume linux
#include <pthread.h>

class AsanLock {
 public:
  AsanLock() {
    CHECK(0 == pthread_mutex_init(&mu_, NULL));
  }
  ~AsanLock() {
    CHECK(0 == pthread_mutex_destroy(&mu_));
  }
  void Lock() {
    CHECK(0 == pthread_mutex_lock(&mu_));
  }
  void Unlock() {
    CHECK(0 == pthread_mutex_unlock(&mu_));
  }
 private:
  pthread_mutex_t mu_;
};

#endif

class ScopedLock {
 public:
  ScopedLock(AsanLock *mu) : mu_(mu) {
    mu_->Lock();
  }
  ~ScopedLock() {
    mu_->Unlock();
  }
 private:
  AsanLock *mu_;
};



#endif  // ASAN_LOCK_H
