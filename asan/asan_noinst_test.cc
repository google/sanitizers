// Copyright 2011 Google Inc. All Rights Reserved.
// Author: kcc@google.com (Kostya Serebryany)


#include <stdio.h>
#include "gtest/gtest.h"

#include "asan_int.h"


TEST(AddressSanitizer, InternalMallocTest) {
  void *ptr = __asan_memalign(10, 128);
  __asan_free(ptr);
}
