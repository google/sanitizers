//===-- asan_interface_test.cc ------------*- C++ -*-===//
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
//===----------------------------------------------------------------------===//
#include <pthread.h>
#include <stdio.h>
#include <string.h>

#include "asan_test_config.h"
#include "asan_test_utils.h"
#include "asan_interface.h"

using __asan_interface::get_current_allocated_bytes;
using __asan_interface::enable_statistics;
using __asan_interface::print_accumulated_stats;

TEST(AddressSanitizerInterface, DISABLED_EnableStatisticsTest) {
  enable_statistics(true);
  EXPECT_EQ(true, enable_statistics(false));
  EXPECT_EQ(false, enable_statistics(false));
}

TEST(AddressSanitizerInterface, DISABLED_GetCurrentAllocatedBytesTest) {
  size_t before_malloc, after_malloc, after_free;
  char *array;
  const size_t kMallocSize = 100;
  enable_statistics(true);
  before_malloc = get_current_allocated_bytes();

  array = Ident((char*)malloc(kMallocSize));
  after_malloc = get_current_allocated_bytes();
  EXPECT_EQ(before_malloc + kMallocSize, after_malloc);

  free(array);
  after_free = get_current_allocated_bytes();
  EXPECT_EQ(before_malloc, after_free);

  enable_statistics(false);
  array = Ident((char*)malloc(kMallocSize));
  after_malloc = get_current_allocated_bytes();
  EXPECT_EQ(before_malloc, after_malloc);

  free(array);
}

static const size_t kManyThreadsMallocSizes[] = {5, 1UL<<10, 1UL<<20, 357};
static const size_t kManyThreadsIterations = 150;
static const size_t kManyThreadsNumThreads = 150;

void *ManyThreadsWithStatsWorker(void *arg) {
  for (size_t iter = 0; iter < kManyThreadsIterations; iter++) {
    for (size_t size_index = 0; size_index < 4; size_index++) {
      free(Ident(malloc(kManyThreadsMallocSizes[size_index])));
    }
  }
  if ((size_t)arg % 15 == 0) {
    print_accumulated_stats();
  }
  return 0;
}

TEST(AddressSanitizerInterface, DISABLED_ManyThreadsWithStatsStressTest) {
  size_t before_test, after_test, i;
  pthread_t threads[kManyThreadsNumThreads];
  enable_statistics(true);
  before_test = get_current_allocated_bytes();
  for (i = 0; i < kManyThreadsNumThreads; i++) {
    pthread_create(&threads[i], 0,
                   (void* (*)(void *x))ManyThreadsWithStatsWorker, (void*)i);
  }
  for (i = 0; i < kManyThreadsNumThreads; i++) {
    pthread_join(threads[i], 0);
  }
  after_test = get_current_allocated_bytes();
  enable_statistics(false);
  print_accumulated_stats();
}

