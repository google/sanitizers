/* Copyright 2012 Google Inc.
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

// NOTE: Don't put <windows.h> here as it's large and not needed for tiny tests.

#include <assert.h>
#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { \
  printf("Oops: %s @ %s:%d\n", #x, __FILE__, __LINE__); abort(); \
} } while(0)

#define DLLEXPORT extern "C" __declspec(dllexport)

__declspec(noinline)
void* ident(volatile void *p) {
  return (void*)p;
}

__declspec(noinline)
int ident(volatile int x) {
  return x;
}

void free_noopt(volatile void *p) {
  free(ident(p));
}

void UNREACHABLE() {
  printf("This code should be unreachable\n");
  fflush(stdout);
}
