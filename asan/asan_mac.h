//===-- asan_mac.h ---------------------*- C++ -*-===//
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
// ASan-private header for asan_mac.cc
//===----------------------------------------------------------------------===//
#ifndef ASAN_MAC_H
#define ASAN_MAC_H

#include "asan_interceptors.h"

// TODO(glider): need to check if the OS X version is 10.6 or greater.
#include <dispatch/dispatch.h>
#include <setjmp.h>

typedef void (*dispatch_function_t)(void *block);
typedef int (*dispatch_async_f_f)(dispatch_queue_t dq, void *ctxt,
                                  dispatch_function_t func);
typedef int (*dispatch_after_f_f)(dispatch_time_t when,
                                  dispatch_queue_t dq, void *ctxt,
                                  dispatch_function_t func);

// A wrapper for the ObjC blocks used to support libdispatch.
typedef struct {
  void *block;
  dispatch_function_t func;
  int parent_tid;
} asan_block_context_t;

extern "C"
int WRAP(dispatch_async_f)(dispatch_queue_t dq,
                           void *ctxt,
                           dispatch_function_t func);
extern "C"
int WRAP(dispatch_after_f)(dispatch_time_t when,
                           dispatch_queue_t dq,
                           void *ctxt,
                           dispatch_function_t func);

#endif  // ASAN_MAC_H
