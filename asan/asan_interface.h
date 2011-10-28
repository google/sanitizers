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
// All functions in this header as extern "C" and start with __asan_.

extern "C" {
  // Returns the estimated number of bytes that will be reserved by allocator
  // for request of "size" bytes. If ASan allocator can't allocate that much
  // memory, returns the maximal possible allocation size, otherwise returns
  // "size".
  size_t __asan_get_estimated_allocated_size(size_t size);
  // Returns true if p is NULL or if p was returned by the ASan allocator and
  // is not yet freed.
  bool __asan_get_ownership(const void *p);
  // Returns the number of bytes reserved for the pointer p.
  // Requires (get_ownership(p) == true).
  size_t __asan_get_allocated_size(const void *p);
  // Number of bytes, allocated and not yet freed by the application.
  size_t __asan_get_current_allocated_bytes();
  // Turns on/off statistics update. Returns the previous value.
  bool __asan_enable_statistics(bool enable);
  // Prints accumulated stats to stderr. Used for debugging.
  void __asan_print_accumulated_stats();
}  // namespace

#endif  // ASAN_INTERFACE_H
