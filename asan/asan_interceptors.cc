//===-- asan_interceptors.cc ------------*- C++ -*-===//
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
// Intercept various libc functions to catch buggy memory accesses there.
//===----------------------------------------------------------------------===//
#include "asan_interceptors.h"

#include "asan_allocator.h"
#include "asan_interface.h"
#include "asan_internal.h"
#include "asan_mapping.h"
#include "asan_stack.h"
#include "asan_stats.h"

#include <dlfcn.h>
#include <string.h>

bool __asan_flag_replace_str;
bool __asan_flag_replace_intrin;

namespace __asan {
memcpy_f      real_memcpy;
memmove_f     real_memmove;
memset_f      real_memset;
strlen_f      real_strlen;
strncpy_f     real_strncpy;
}  // namespace

// This implementation is used in interceptors of
// glibc str* functions to instrument memory range accesses.
static size_t __asan_strnlen(const char *s, size_t maxlen) {
  size_t i = 0;
  while (i < maxlen && s[i]) i++;
  return i;
}

// Instruments read/write access to a single byte in memory.
// On error calls __asan_report_error, which aborts the program.
__attribute__((noinline))
static void AccessAddress(uintptr_t address, bool isWrite) {
  const size_t kAccessSize = 1;
  uint8_t *shadow_address = (uint8_t*)MemToShadow(address);
  int8_t shadow_value = *shadow_address;
  if (shadow_value) {
    uint8_t last_accessed_byte = (address & (SHADOW_GRANULARITY - 1))
                                 + kAccessSize - 1;
    if (last_accessed_byte >= shadow_value) {
      GET_BP_PC_SP;
      __asan_report_error(pc, bp, sp, address, isWrite, kAccessSize);
    }
  }
}

// We implement ACCESS_MEMORY_RANGE, ASAN_READ_RANGE,
// and ASAN_WRITE_RANGE as macro instead of function so
// that no extra frames are created, and stack trace contains
// relevant information only.

// Instruments read/write access to a memory range.
// More complex implementation is possible, for now just
// checking the first and the last byte of a range.
#define ACCESS_MEMORY_RANGE(offset, size, isWrite) do { \
  if (size > 0) { \
    uintptr_t ptr = (uintptr_t)(offset); \
    AccessAddress(ptr, isWrite); \
    AccessAddress(ptr + (size) - 1, isWrite); \
  } \
} while (0);

#define ASAN_READ_RANGE(offset, size) do { \
  ACCESS_MEMORY_RANGE(offset, size, false); \
} while (0);

#define ASAN_WRITE_RANGE(offset, size) do { \
  ACCESS_MEMORY_RANGE(offset, size, true); \
} while (0);

static inline void ensure_asan_inited() {
  CHECK(!__asan_init_is_running);
  if (!__asan_inited) {
    __asan_init();
  }
}

#if 0
// Interceptors for memcpy/memmove/memset are disabled for now.
// They are handled by the LLVM module anyway.
void *WRAP(memcpy)(void *to, const void *from, size_t size) {
  // memcpy is called during __asan_init() from the internals
  // of printf(...).
  if (__asan_init_is_running) {
    return __asan::real_memcpy(to, from, size);
  }
  ensure_asan_inited();
  if (__asan_flag_replace_intrin) {
    ASAN_WRITE_RANGE(from, size);
    ASAN_READ_RANGE(to, size);
    // TODO(samsonov): Check here that read and write intervals
    // do not overlap.
  }
  return __asan::real_memcpy(to, from, size);
}

void *WRAP(memmove)(void *to, const void *from, size_t size) {
  ensure_asan_inited();
  if (__asan_flag_replace_intrin) {
    ASAN_WRITE_RANGE(from, size);
    ASAN_READ_RANGE(to, size);
  }
  return __asan::real_memmove(to, from, size);
}

void *WRAP(memset)(void *block, int c, size_t size) {
  ensure_asan_inited();
  if (__asan_flag_replace_intrin) {
    ASAN_WRITE_RANGE(block, size);
  }
  return __asan::real_memset(block, c, size);
}
#endif

size_t WRAP(strlen)(const char *s) {
  // strlen is called during __asan_init() from library
  // functions on Mac: malloc_default_purgeable_zone()
  // in ReplaceSystemAlloc().
  if (__asan_init_is_running) {
    return __asan::real_strlen(s);
  }
  ensure_asan_inited();
  // TODO(samsonov): We should predict possible OOB access in
  // real_strlen() call, and instrument its arguments
  // beforehand.
  size_t length = __asan::real_strlen(s);
  if (__asan_flag_replace_str) {
    ASAN_READ_RANGE(s, length + 1);
  }
  return length;
}

char *WRAP(strncpy)(char *to, const char *from, size_t size) {
  ensure_asan_inited();
  if (__asan_flag_replace_str) {
    // TODO(samsonov): We should be able to find *the first*
    // OOB access that happens in __asan_strlen.
    size_t from_size = __asan_strnlen(from, size) + 1;
    if (from_size > size) {
      from_size = size;
    }
    ASAN_READ_RANGE(from, from_size);
    ASAN_WRITE_RANGE(to, size);
  }
  return __asan::real_strncpy(to, from, size);
}

size_t __asan::internal_strlen(const char *s) {
  size_t i = 0;
  while (s[i]) i++;
  return i;
}

void __asan_interceptors_init() {
#ifndef __APPLE__
  INTERCEPT_FUNCTION(memcpy);
  INTERCEPT_FUNCTION(memmove);
  INTERCEPT_FUNCTION(memset);
#else
  __asan::real_memcpy = memcpy;
  __asan::real_memmove = memmove;
  __asan::real_memset = memset;
#endif
  INTERCEPT_FUNCTION(strlen);
  INTERCEPT_FUNCTION(strncpy);
  if (__asan_flag_v > 0) {
    Printf("AddressSanitizer: libc interceptors initialized\n");
  }
}
