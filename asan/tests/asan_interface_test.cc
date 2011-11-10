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

TEST(AddressSanitizerInterface, GetEstimatedAllocatedSize) {
  EXPECT_EQ(1, __asan_get_estimated_allocated_size(0));
  const size_t sizes[] = { 1, 30, 1<<30 };
  for (size_t i = 0; i < 3; i++) {
    EXPECT_EQ(sizes[i], __asan_get_estimated_allocated_size(sizes[i]));
  }
}

static const char* kGetAllocatedSizeErrorMsg =
  "__asan_get_allocated_size failed";

TEST(AddressSanitizerInterface, GetAllocatedSizeAndOwnershipTest) {
  const size_t kArraySize = 100;
  char *array = Ident((char*)malloc(kArraySize));
  int *int_ptr = Ident(new int);
  size_t alloc_size;

  // Allocated memory is owned by allocator. Allocated size should be
  // equal to requested size.
  EXPECT_EQ(true, __asan_get_ownership(array));
  EXPECT_EQ(kArraySize, __asan_get_allocated_size(array));
  EXPECT_EQ(true, __asan_get_ownership(int_ptr));
  EXPECT_EQ(sizeof(int), __asan_get_allocated_size(int_ptr));

  // We cannot call GetAllocatedSize from the memory we didn't map,
  // and from the interior pointers (not returned by previous malloc).
  void *wild_addr = (void*)0x1;
  EXPECT_EQ(false, __asan_get_ownership(wild_addr));
  EXPECT_DEATH(__asan_get_allocated_size(wild_addr), kGetAllocatedSizeErrorMsg);
  EXPECT_EQ(false, __asan_get_ownership(array + kArraySize / 2));
  EXPECT_DEATH(__asan_get_allocated_size(array + kArraySize / 2),
               kGetAllocatedSizeErrorMsg);

  // NULL is a valid argument and is owned.
  EXPECT_EQ(true, __asan_get_ownership(NULL));
  EXPECT_EQ(0, __asan_get_allocated_size(NULL));

  // When memory is freed, it's not owned, and call to GetAllocatedSize
  // is forbidden.
  free(array);
  EXPECT_EQ(false, __asan_get_ownership(array));
  EXPECT_DEATH(__asan_get_allocated_size(array), kGetAllocatedSizeErrorMsg);

  delete int_ptr;
}

TEST(AddressSanitizerInterface, EnableStatisticsTest) {
  bool old_stats_value = __asan_enable_statistics(true);
  EXPECT_EQ(true, __asan_enable_statistics(false));
  EXPECT_EQ(false, __asan_enable_statistics(old_stats_value));
}

TEST(AddressSanitizerInterface, GetCurrentAllocatedBytesTest) {
  size_t before_malloc, after_malloc, after_free;
  char *array;
  const size_t kMallocSize = 100;
  bool old_stats_value = __asan_enable_statistics(true);
  before_malloc = __asan_get_current_allocated_bytes();

  array = Ident((char*)malloc(kMallocSize));
  after_malloc = __asan_get_current_allocated_bytes();
  EXPECT_EQ(before_malloc + kMallocSize, after_malloc);

  free(array);
  after_free = __asan_get_current_allocated_bytes();
  EXPECT_EQ(before_malloc, after_free);

  __asan_enable_statistics(false);
  array = Ident((char*)malloc(kMallocSize));
  after_malloc = __asan_get_current_allocated_bytes();
  EXPECT_EQ(before_malloc, after_malloc);

  free(array);
  __asan_enable_statistics(old_stats_value);
}

// This test is run in a separate process, so that large malloced
// chunk won't remain in the free lists after the test.
// Note: use ASSERT_* instead of EXPECT_* here.
void RunGetHeapSizeTestAndDie() {
  size_t old_heap_size, new_heap_size, heap_growth;
  // We unlikely have have chunk of this size in free list.
  static const size_t kLargeMallocSize = 1 << 29;  // 512M
  __asan_enable_statistics(true);
  old_heap_size = __asan_get_heap_size();
  fprintf(stderr, "allocating %zu bytes:\n", kLargeMallocSize);
  free(Ident(malloc(kLargeMallocSize)));
  new_heap_size = __asan_get_heap_size();
  heap_growth = new_heap_size - old_heap_size;
  fprintf(stderr, "heap growth after first malloc: %zu\n", heap_growth);
  ASSERT_GE(heap_growth, kLargeMallocSize);
  ASSERT_LE(heap_growth, 2 * kLargeMallocSize);

  // Now large chunk should fall into free list, and can be
  // allocated without increasing heap size.
  old_heap_size = new_heap_size;
  free(Ident(malloc(kLargeMallocSize)));
  heap_growth = __asan_get_heap_size() - old_heap_size;
  fprintf(stderr, "heap growth after second malloc: %zu\n", heap_growth);
  ASSERT_LT(heap_growth, kLargeMallocSize);

  // Test passed. Now die with expected double-free.
  int *x = Ident(new int);
  delete Ident(x);
  delete Ident(x);
}

TEST(AddressSanitizerInterface, GetHeapSizeTest) {
  EXPECT_DEATH(RunGetHeapSizeTestAndDie(), "double-free");
}

static const size_t kManyThreadsMallocSizes[] = {5, 1UL<<10, 1UL<<20, 357};
static const size_t kManyThreadsIterations = 250;
static const size_t kManyThreadsNumThreads = 200;

void *ManyThreadsWithStatsWorker(void *arg) {
  for (size_t iter = 0; iter < kManyThreadsIterations; iter++) {
    for (size_t size_index = 0; size_index < 4; size_index++) {
      free(Ident(malloc(kManyThreadsMallocSizes[size_index])));
    }
  }
  return 0;
}

TEST(AddressSanitizerInterface, ManyThreadsWithStatsStressTest) {
  size_t before_test, after_test, i;
  pthread_t threads[kManyThreadsNumThreads];
  bool old_stats_value = __asan_enable_statistics(true);
  before_test = __asan_get_current_allocated_bytes();
  for (i = 0; i < kManyThreadsNumThreads; i++) {
    pthread_create(&threads[i], 0,
                   (void* (*)(void *x))ManyThreadsWithStatsWorker, (void*)i);
  }
  for (i = 0; i < kManyThreadsNumThreads; i++) {
    pthread_join(threads[i], 0);
  }
  after_test = __asan_get_current_allocated_bytes();
  // ASan stats also reflect memory usage of internal ASan RTL structs,
  // so we can't check for equality here.
  EXPECT_LT(after_test, before_test + (1UL<<20));
  __asan_enable_statistics(old_stats_value);
}
