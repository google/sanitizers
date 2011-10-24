//===-- asan_interface.h ------------*- C++ -*-===//
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
// This header can be included by the instrumented program to fetch
// data (mostly allocator statistics) from ASan runtime library.
//===----------------------------------------------------------------------===//
#ifndef ASAN_INTERFACE_H
#define ASAN_INTERFACE_H

// This header should NOT include any other headers from ASan runtime.

namespace __asan_interface {
  // Number of bytes, allocated and not yet freed by the application.
  size_t get_current_allocated_bytes();
  // Turns on/off statistics update. Returns the previous value.
  bool enable_statistics(bool enable);
  // Prints accumulated stats to stderr. Used for debugging.
  void print_accumulated_stats();
}  // namespace

#endif  // ASAN_INTERFACE_H
