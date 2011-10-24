//===-- asan_lock.h ------------*- C++ -*-===//
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
// A wrapper for a simple lock.
//===----------------------------------------------------------------------===//
#ifndef ASAN_LOCK_H
#define ASAN_LOCK_H

#include "asan_int.h"

#ifdef __APPLE__
#include <pthread.h>

#include <libkern/OSAtomic.h>
class AsanLock {
 public:
  AsanLock() {
    mu_ = OS_SPINLOCK_INIT;
    is_locked_ = false;
    owner_ = 0;
  }
  ~AsanLock() {}
  void Lock() {
    CHECK(owner_ != pthread_self());
    OSSpinLockLock(&mu_);
    is_locked_ = true;
    owner_ = pthread_self();
  }
  void Unlock() {
    owner_ = 0;
    is_locked_ = false;
    OSSpinLockUnlock(&mu_);
  }

  bool IsLocked() {
    // This is not atomic, e.g. one thread may get different values if another
    // one is about to release the lock.
    return is_locked_;
  }
 private:
  OSSpinLock mu_;
  volatile pthread_t owner_;  // for debugging purposes
  bool is_locked_;  // for silly malloc_introspection_t interface
};

#else  // assume linux
#include <pthread.h>

class AsanLock {
 public:
  AsanLock() {
    pthread_mutex_init(&mu_, NULL);
    // pthread_spin_init(&mu_, NULL);
  }
  ~AsanLock() {
    pthread_mutex_destroy(&mu_);
    // pthread_spin_destroy(&mu_);
  }
  void Lock() {
    pthread_mutex_lock(&mu_);
    // pthread_spin_lock(&mu_);
  }
  void Unlock() {
    pthread_mutex_unlock(&mu_);
    // pthread_spin_unlock(&mu_);
  }
 private:
  pthread_mutex_t mu_;
  // pthread_spinlock_t mu_;
};

#endif

class ScopedLock {
 public:
  explicit ScopedLock(AsanLock *mu) : mu_(mu) {
    mu_->Lock();
  }
  ~ScopedLock() {
    mu_->Unlock();
  }
 private:
  AsanLock *mu_;
};



#endif  // ASAN_LOCK_H
