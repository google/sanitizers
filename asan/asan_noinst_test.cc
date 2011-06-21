// Copyright 2011 Google Inc. All Rights Reserved.
// Author: kcc@google.com (Kostya Serebryany)

#include "asan_int.h"

#include <stdio.h>
#include <stdlib.h>
#include <vector>
#include "gtest/gtest.h"

using namespace std;

static void MallocStress(size_t n) {
  vector<void *> vec;
  for (size_t i = 0; i < n; i++) {
    if ((i % 3) == 0) {
      if (vec.empty()) continue;
      size_t idx = rand() % vec.size();
      void *ptr = vec[idx];
      vec[idx] = vec.back();
      vec.pop_back();
      __asan_free(ptr, 0, 0);
    } else {
      size_t size = rand() % 1000 + 1;
      size_t alignment = 1 << (rand() % 10 + 1);
      void *ptr = __asan_memalign(size, alignment, 0, 0);
      vec.push_back(ptr);
      for (size_t i = 0; i < size; i++) {
        *((char*)ptr) = 0;
      }
    }
  }
  for (size_t i = 0; i < vec.size(); i++)
    __asan_free(vec[i], 0, 0);
}


TEST(AddressSanitizer, InternalMallocTest) {
  MallocStress(2000000);
}
