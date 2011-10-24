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

using __asan_interface::get_ownership;
using __asan_interface::get_allocated_size;
using __asan_interface::get_current_allocated_bytes;
using __asan_interface::enable_statistics;
using __asan_interface::print_accumulated_stats;

static const char* kGetAllocatedSizeErrorMsg = "get_allocated_size failed";

TEST(AddressSanitizerInterface, GetAllocatedSizeAndOwnershipTest) {
  const size_t kArraySize = 100;
  char *array = Ident((char*)malloc(kArraySize));
  int *int_ptr = Ident(new int);
  size_t alloc_size;

  // Allocated memory is owned by allocator. Allocated size should be
  // equal to requested size.
  EXPECT_EQ(true, get_ownership(array));
  EXPECT_EQ(kArraySize, get_allocated_size(array));
  EXPECT_EQ(true, get_ownership(int_ptr));
  EXPECT_EQ(sizeof(int), get_allocated_size(int_ptr));

  // We cannot call GetAllocatedSize from the memory we didn't map,
  // and from the interior pointers (not returned by previous malloc).
  void *wild_addr = (void*)0x1;
  EXPECT_EQ(false, get_ownership(wild_addr));
  EXPECT_DEATH(get_allocated_size(wild_addr), kGetAllocatedSizeErrorMsg);
  EXPECT_EQ(false, get_ownership(array + kArraySize / 2));
  EXPECT_DEATH(get_allocated_size(array + kArraySize / 2),
               kGetAllocatedSizeErrorMsg);

  // NULL is a valid argument and is owned.
  EXPECT_EQ(true, get_ownership(NULL));
  EXPECT_EQ(0, get_allocated_size(NULL));

  // When memory is freed, it's not owned, and call to GetAllocatedSize
  // is forbidden.
  free(array);
  EXPECT_EQ(false, get_ownership(array));
  EXPECT_DEATH(get_allocated_size(array), kGetAllocatedSizeErrorMsg);

  delete int_ptr;
}

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
