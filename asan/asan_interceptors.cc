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
#include "asan_int.h"
#include "asan_mapping.h"
#include "asan_stack.h"
#include "asan_stats.h"
#ifdef __APPLE__
#include "mach_override.h"
#endif

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

static void __asan_read_range(const void *offset, size_t size);
static void __asan_write_range(const void *offset, size_t size);

static size_t __asan_strnlen(const char *s, size_t maxlen);

static inline void ensure_asan_inited() {
  CHECK(!__asan_init_is_running);
  if (!__asan_inited) {
    __asan_init();
  }
}

void *WRAP(memcpy)(void *to, const void *from, size_t size) {
  // memcpy is called during __asan_init() from the internals
  // of printf(...).
  if (__asan_init_is_running) {
    return __asan::real_memcpy(to, from, size);
  }
  ensure_asan_inited();
  if (__asan_flag_replace_intrin) {
    __asan_write_range(from, size);
    __asan_read_range(to, size);
    // TODO(samsonov): Check here that read and write intervals
    // do not overlap.
  }
  return __asan::real_memcpy(to, from, size);
}

void *WRAP(memmove)(void *to, const void *from, size_t size) {
  ensure_asan_inited();
  if (__asan_flag_replace_intrin) {
    __asan_write_range(from, size);
    __asan_read_range(to, size);
  }
  return __asan::real_memmove(to, from, size);
}

void *WRAP(memset)(void *block, int c, size_t size) {
  ensure_asan_inited();
  if (__asan_flag_replace_intrin) {
    __asan_write_range(block, size);
  }
  return __asan::real_memset(block, c, size);
}

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
    __asan_read_range(s, length + 1);
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
    __asan_read_range(from, from_size);
    __asan_write_range(to, size);
  }
  return __asan::real_strncpy(to, from, size);
}

size_t __asan::internal_strlen(const char *s) {
  size_t i = 0;
  while (s[i]) i++;
  return i;
}

void __asan_interceptors_init() {
  INTERCEPT_FUNCTION(memcpy);
  INTERCEPT_FUNCTION(memmove);
  INTERCEPT_FUNCTION(memset);
  INTERCEPT_FUNCTION(strlen);
  INTERCEPT_FUNCTION(strncpy);
  if (__asan_flag_v > 0) {
    Printf("AddressSanitizer: libc interceptors initialized\n");
  }
}

// This implementation is used in interceptors of
// glibc str* functions to instrument memory range accesses.
static size_t __asan_strnlen(const char *s, size_t maxlen) {
  size_t i = 0;
  while (i < maxlen && s[i]) i++;
  return i;
}

// Instrument read/write access to a single byte in memory.
static void AccessAddress(uint8_t *address, bool isWrite) {
  uint8_t *shadow_address = (uint8_t*)MemToShadow((uintptr_t)address);
  int8_t shadow_value = *shadow_address;
  if (shadow_value) {
    uint8_t last_addressed_byte =
        (uintptr_t(address) & (SHADOW_GRANULARITY - 1)) + 1;
    if (last_addressed_byte <= shadow_value) {
      return;
    }
    __asan_report_error((uintptr_t)address, isWrite, 1);
  }
}

// Instrument read/write access to a memory range.
// More complex implementation is possible, for now just
// checking the first and the last byte of a range.
static void AccessMemoryRange(uint8_t *ptr, size_t size, bool isWrite) {
  if (size == 0) return;
  AccessAddress(ptr, isWrite);
  AccessAddress(ptr + size - 1, isWrite);
}

static void __asan_read_range(const void *offset, size_t size) {
  AccessMemoryRange((uint8_t*)offset, size, false);
}

static void __asan_write_range(const void *offset, size_t size) {
  AccessMemoryRange((uint8_t*)offset, size, true);
}
