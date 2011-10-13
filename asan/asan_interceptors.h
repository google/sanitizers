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

#ifndef ASAN_INTERCEPTORS_H
#define ASAN_INTERCEPTORS_H

#include "asan_int.h"
#include "asan_stack.h"

// To replace weak system functions on Linux we just need to declare functions
// with same names in our library and then obtain the real function pointers
// using dlsym(). This is not so on Mac OS, where the two-level namespace makes
// our replacement functions invisible to other libraries. This may be overcomed
// using the DYLD_FORCE_FLAT_NAMESPACE, but some errors loading the shared
// libraries in Chromium were noticed when doing so.
// Instead we use mach_override, a handy framework for patching functions at
// runtime. To avoid possible name clashes, our replacement functions have
// the "wrap_" prefix on Mac.
//
// After interception, the calls to system functions will be substituted by
// calls to our interceptors. We store pointers to system function f()
// in __asan::real_f().
#ifdef __APPLE__
#define WRAP(x) wrap_##x
#else
#define WRAP(x) x
#endif

// TODO(glider): mach_override_ptr() tends to spend too much time
// in allocateBranchIsland(). This should be ok for real-word
// application, but slows down our tests which fork too many children.
#ifdef __APPLE__
#define INTERCEPT_FUNCTION(func)                                        \
  CHECK(0 == mach_override_ptr((void*)(func),                           \
                               (void*)WRAP(func),                       \
                               (void**)&__asan::real_##func));          \
  CHECK(__asan::real_##func != NULL);
#else
#define INTERCEPT_FUNCTION(func)                                        \
  CHECK((__asan::real_##func = (func##_f)dlsym(RTLD_NEXT, #func)));
#endif

typedef void* (*memcpy_f)(void *to, const void *from, size_t size);
typedef void* (*memmove_f)(void *to, const void *from, size_t size);
typedef void* (*memset_f)(void *block, int c, size_t size);
typedef size_t (*strlen_f)(const char *s);
typedef char* (*strncpy_f)(char *to, const char *from, size_t size);

// __asan::real_X() holds pointer to library implementation of X().
// __asan::internal_X() is the implementation of X() for use in RTL.
namespace __asan {
extern memcpy_f         real_memcpy;
extern memmove_f        real_memmove;
extern memset_f         real_memset;
extern strlen_f         real_strlen;
extern strncpy_f        real_strncpy;

size_t internal_strlen(const char *s);
}  // namespace

// Initializes pointers to str*/mem* functions.
void __asan_interceptors_init();

#endif  // ASAN_INTERCEPTORS_H
