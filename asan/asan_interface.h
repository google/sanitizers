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

#include <stdint.h>  // for __WORDSIZE
#include <stdlib.h>  // for size_t

// This header should NOT include any other headers from ASan runtime.
// All functions in this header are extern "C" and start with __asan_.

extern "C" {
  // This function should be called at the very beginning of the process,
  // before any instrumented code is executed and before any call to malloc.
  void __asan_init()
      __attribute__((visibility("default")));

  // This function should be called by the instrumented code.
  // 'addr' is the address of a global variable called 'name' of 'size' bytes.
  void __asan_register_global(uintptr_t addr, size_t size, const char *name)
      __attribute__((visibility("default")));

  // This structure describes an instrumented global variable.
  struct __asan_global {
    size_t beg;                // The address of the global.
    size_t size;               // The original size of the global.
    size_t size_with_redzone;  // The size with the redzone.
    const char *name;          // Name as a C string.
  };

  // This function should be called by the instrumented code.
  // gets an array of structures describing globals.
  void __asan_register_globals(__asan_global *globals, size_t n)
      __attribute__((visibility("default")));

  // These two functions are used by the instrumented code in the
  // use-after-return mode. __asan_stack_malloc allocates size bytes of
  // fake stack and asan_free deallocates it. real_stack is a pointer to
  // the real stack region.
  size_t __asan_stack_malloc(size_t size, size_t real_stack)
      __attribute__((visibility("default")));
  void __asan_stack_free(size_t ptr, size_t size, size_t real_stack)
      __attribute__((visibility("default")));

  // This is an internal function that is called to report an error.
  // However it is still a part of the interface because users may want to
  // set a breakpoint on this function in a debugger.
  void __asan_report_error(uintptr_t pc, uintptr_t bp, uintptr_t sp,
                           uintptr_t addr, bool is_write, size_t access_size)
    __attribute__((visibility("default")));

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
  // Number of bytes, mmaped by asan allocator to fulfill allocation requests.
  // Generally, for request of X bytes, allocator can reserve and add to free
  // lists a large number of chunks of size X to use them for future requests.
  // All these chunks count toward the heap size. Currently, allocator never
  // releases memory to OS (instead, it just puts freed chunks to free lists).
  size_t __asan_get_heap_size();
  // Turns on/off statistics update. Returns the previous value.
  bool __asan_enable_statistics(bool enable);
  // Prints accumulated stats to stderr. Used for debugging.
  void __asan_print_accumulated_stats();
  // Returns the number of bytes maped by the asan allocator.
  // This does not include the shadow memory.
  size_t __asan_total_mmaped();
}  // namespace

#endif  // ASAN_INTERFACE_H
