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


#include "asan_int.h"
#include "asan_stack.h"
#include "asan_allocator.h"

#include <stdio.h>
#include <stdlib.h>
#include <vector>
#include "gtest/gtest.h"

using namespace std;

static void MallocStress(size_t n) {
  AsanStackTrace stack1;
  stack1.trace[0] = 0xa123;
  stack1.trace[1] = 0xa456;
  stack1.size = 2;

  AsanStackTrace stack2;
  stack2.trace[0] = 0xb123;
  stack2.trace[1] = 0xb456;
  stack2.size = 2;

  AsanStackTrace stack3;
  stack3.trace[0] = 0xc123;
  stack3.trace[1] = 0xc456;
  stack3.size = 2;

  vector<void *> vec;
  for (size_t i = 0; i < n; i++) {
    if ((i % 3) == 0) {
      if (vec.empty()) continue;
      size_t idx = rand() % vec.size();
      void *ptr = vec[idx];
      vec[idx] = vec.back();
      vec.pop_back();
      __asan_free(ptr, &stack1);
    } else {
      size_t size = rand() % 1000 + 1;
      size_t alignment = 1 << (rand() % 10 + 1);
      void *ptr = __asan_memalign(alignment, size, &stack2);
      vec.push_back(ptr);
      for (size_t i = 0; i < size; i++) {
        *((char*)ptr) = 0;
      }
    }
  }
  for (size_t i = 0; i < vec.size(); i++)
    __asan_free(vec[i], &stack3);
}


TEST(AddressSanitizer, InternalMallocTest) {
  MallocStress(2000000);
}
