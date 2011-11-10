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

#include <algorithm>
#include <dlfcn.h>
#include <string.h>

namespace __asan {

index_f       real_index;
memcpy_f      real_memcpy;
memmove_f     real_memmove;
memset_f      real_memset;
strchr_f      real_strchr;
strcpy_f      real_strcpy;
strdup_f      real_strdup;
strlen_f      real_strlen;
strncpy_f     real_strncpy;
strnlen_f     real_strnlen;

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

// Behavior of functions like "memcpy" or "strcpy" is undefined
// if memory intervals overlap. We report error in this case.
// Macro is used to avoid creation of new frames.
static inline bool RangesOverlap(const char *offset1, const char *offset2,
                                 size_t length) {
  return !((offset1 + length <= offset2) || (offset2 + length <= offset1));
}
#define CHECK_RANGES_OVERLAP(_offset1, _offset2, length) do { \
  const char *offset1 = (const char*)_offset1; \
  const char *offset2 = (const char*)_offset2; \
  if (RangesOverlap((const char*)offset1, (const char*)offset2, \
                    length)) { \
    Printf("ERROR: AddressSanitizer strcpy-param-overlap: " \
           "memory ranges [%p,%p) and [%p, %p) overlap\n", \
           offset1, offset1 + length, offset2, offset2 + length); \
    PRINT_CURRENT_STACK(); \
    ShowStatsAndAbort(); \
  } \
} while (0);

static inline void ensure_asan_inited() {
  CHECK(!asan_init_is_running);
  if (!asan_inited) {
    __asan_init();
  }
}


size_t internal_strlen(const char *s) {
  size_t i = 0;
  while (s[i]) i++;
  return i;
}

size_t internal_strnlen(const char *s, size_t maxlen) {
  if (real_strnlen != NULL) {
    return real_strnlen(s, maxlen);
  }
  size_t i = 0;
  while (i < maxlen && s[i]) i++;
  return i;
}

void InitializeAsanInterceptors() {
#ifndef __APPLE__
  INTERCEPT_FUNCTION(index);
#else
  OVERRIDE_FUNCTION(index, WRAP(strchr));
#endif
#ifndef __APPLE__
  INTERCEPT_FUNCTION(memcpy);
  INTERCEPT_FUNCTION(memmove);
  INTERCEPT_FUNCTION(memset);
#else
  real_memcpy = memcpy;
  real_memmove = memmove;
  real_memset = memset;
#endif
  INTERCEPT_FUNCTION(strchr);
  INTERCEPT_FUNCTION(strcpy);  // NOLINT
  INTERCEPT_FUNCTION(strdup);
  INTERCEPT_FUNCTION(strlen);
  INTERCEPT_FUNCTION(strncpy);
#ifndef __APPLE__
  INTERCEPT_FUNCTION(strnlen);
#endif
  if (FLAG_v > 0) {
    Printf("AddressSanitizer: libc interceptors initialized\n");
  }
}

}  // namespace __asan

// ---------------------- Wrappers ---------------- {{{1
using namespace __asan;  // NOLINT

#ifndef __APPLE__
const char *WRAP(index)(const char *string, int c)
  __attribute__((alias(WRAPPER_NAME(strchr))));
#endif

#if 0
// Interceptors for memcpy/memmove/memset are disabled for now.
// They are handled by the LLVM module anyway.
void *WRAP(memcpy)(void *to, const void *from, size_t size) {
  // memcpy is called during __asan_init() from the internals
  // of printf(...).
  if (asan_init_is_running) {
    return real_memcpy(to, from, size);
  }
  ensure_asan_inited();
  if (FLAG_replace_intrin) {
    CHECK_RANGES_OVERLAP(to, from, size);
    ASAN_WRITE_RANGE(from, size);
    ASAN_READ_RANGE(to, size);
  }
  return real_memcpy(to, from, size);
}

void *WRAP(memmove)(void *to, const void *from, size_t size) {
  ensure_asan_inited();
  if (FLAG_replace_intrin) {
    ASAN_WRITE_RANGE(from, size);
    ASAN_READ_RANGE(to, size);
  }
  return real_memmove(to, from, size);
}

void *WRAP(memset)(void *block, int c, size_t size) {
  ensure_asan_inited();
  if (FLAG_replace_intrin) {
    ASAN_WRITE_RANGE(block, size);
  }
  return real_memset(block, c, size);
}
#endif

const char *WRAP(strchr)(const char *str, int c) {
  ensure_asan_inited();
  char *result = real_strchr(str, c);
  if (FLAG_replace_str) {
    size_t bytes_read = (result ? result - str : real_strlen(str)) + 1;
    ASAN_READ_RANGE(str, bytes_read);
  }
  return result;
}

char *WRAP(strcpy)(char *to, const char *from) {  // NOLINT
  // strcpy is called from malloc_default_purgeable_zone()
  // in __asan::ReplaceSystemAlloc() on Mac.
  if (asan_init_is_running) {
    return real_strcpy(to, from);
  }
  ensure_asan_inited();
  if (FLAG_replace_str) {
    size_t from_size = real_strlen(from) + 1;
    CHECK_RANGES_OVERLAP(to, from, from_size);
    ASAN_READ_RANGE(from, from_size);
    ASAN_WRITE_RANGE(to, from_size);
  }
  return real_strcpy(to, from);
}

char *WRAP(strdup)(const char *s) {
  ensure_asan_inited();
  if (FLAG_replace_str) {
    size_t length = real_strlen(s);
    ASAN_READ_RANGE(s, length + 1);
  }
  return real_strdup(s);
}

size_t WRAP(strlen)(const char *s) {
  // strlen is called from malloc_default_purgeable_zone()
  // in __asan::ReplaceSystemAlloc() on Mac.
  if (asan_init_is_running) {
    return real_strlen(s);
  }
  ensure_asan_inited();
  size_t length = real_strlen(s);
  if (FLAG_replace_str) {
    ASAN_READ_RANGE(s, length + 1);
  }
  return length;
}

char *WRAP(strncpy)(char *to, const char *from, size_t size) {
  ensure_asan_inited();
  if (FLAG_replace_str) {
    size_t from_size = std::min(size, internal_strnlen(from, size) + 1);
    CHECK_RANGES_OVERLAP(to, from, from_size);
    ASAN_READ_RANGE(from, from_size);
    ASAN_WRITE_RANGE(to, size);
  }
  return real_strncpy(to, from, size);
}

#ifndef __APPLE__
size_t WRAP(strnlen)(const char *s, size_t maxlen) {
  ensure_asan_inited();
  size_t length = real_strnlen(s, maxlen);
  if (FLAG_replace_str) {
    ASAN_READ_RANGE(s, std::min(length + 1, maxlen));
  }
  return length;
}
#endif
