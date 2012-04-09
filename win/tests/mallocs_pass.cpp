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

#include "common.h"

int main(void) {
  volatile int *p = (int*)malloc(1024 * sizeof(int));
  p[512] = 0;
  free_noopt(p);

  p = (int*)malloc(128);
  p = (int*)realloc(ident(p), 2048 * sizeof(int));
  p[1024] = 0;
  free_noopt(p);

  p = (int*)calloc(16, sizeof(int));
  assert(p[8] == 0);
  p[15]++;
  assert(16 * sizeof(int) == _msize(ident(p)));
  free_noopt(p);

#if 0
  // Currently fails to build due to http://llvm.org/bugs/show_bug.cgi?id=12332
  p = new int;
  p[0] = 42;
  delete p;
#endif

#if 0
  // Currently fails to build due to http://llvm.org/bugs/show_bug.cgi?id=12332
  p = new int[42];
  p[15]++;
  // delete[] also fails to mangle due to http://llvm.org/bugs/show_bug.cgi?id=12333
  delete [] p;
#endif

  return 0;
}
