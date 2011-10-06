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

#include "asan_interceptors.h"

#include "asan_allocator.h"
#include "asan_int.h"
#include "asan_mapping.h"
#include "asan_stack.h"
#include "asan_stats.h"

#include <dlfcn.h>
#include <stdio.h>

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
  if (!__asan_inited) {
    __asan_init();
  }
}

void *WRAP(memcpy)(void *to, const void *from, size_t size) {
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

void __asan_interceptors_init() {
#ifndef __APPLE__
  CHECK((__asan::real_memcpy = (memcpy_f)dlsym(RTLD_NEXT, "memcpy")));
  CHECK((__asan::real_memmove = (memmove_f)dlsym(RTLD_NEXT, "memmove")));
  CHECK((__asan::real_memset = (memset_f)dlsym(RTLD_NEXT, "memset")));
  CHECK((__asan::real_strlen = (strlen_f)dlsym(RTLD_NEXT, "strlen")));
  CHECK((__asan::real_strncpy = (strncpy_f)dlsym(RTLD_NEXT, "strncpy")));
#else
  // TODO(samsonov): Add Apple implementation here.
#endif
  // TODO(samsonov): Should we output that in verbose mode only?
  Printf("AddressSanitizer: libc interceptors initialized\n");
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
    __asan_report_error((uintptr_t)address, isWrite, /*log_access_size*/ 0);
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
