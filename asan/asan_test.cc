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
// Author: Kostya Serebryany

#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <vector>
#include <pthread.h>
#include <stdint.h>
#include "gtest/gtest.h"

#ifndef __APPLE__
#include <malloc.h>
#endif  // __APPLE__

using namespace std;

typedef unsigned char        U1;
typedef unsigned short       U2;
typedef unsigned int         U4;
typedef unsigned long long   U8;

const size_t kLargeMalloc = 1 << 24;

template<class T>
__attribute__((noinline))
void asan_write(T *a) {
  *a = 0;
}

__attribute__((noinline))
void asan_write_sized_aligned(uint8_t *p, size_t size) {
  EXPECT_EQ(0, ((uintptr_t)p % size));
  if      (size == 1) asan_write((uint8_t*)p);
  else if (size == 2) asan_write((uint16_t*)p);
  else if (size == 4) asan_write((uint32_t*)p);
  else if (size == 8) asan_write((uint64_t*)p);
}

__attribute__((noinline))
void break_optimization() {
 static volatile int a;
 a++;
}


__attribute__((noinline)) void *malloc_fff(size_t size) {
  void *res = malloc/**/(size); break_optimization(); return res;}
__attribute__((noinline)) void *malloc_eee(size_t size) {
  void *res = malloc_fff(size); break_optimization(); return res;}
__attribute__((noinline)) void *malloc_ddd(size_t size) {
  void *res = malloc_eee(size); break_optimization(); return res;}
__attribute__((noinline)) void *malloc_ccc(size_t size) {
  void *res = malloc_ddd(size); break_optimization(); return res;}
__attribute__((noinline)) void *malloc_bbb(size_t size) {
  void *res = malloc_ccc(size); break_optimization(); return res;}
__attribute__((noinline)) void *malloc_aaa(size_t size) {
  void *res = malloc_bbb(size); break_optimization(); return res;}

__attribute__((noinline))
  void free_ccc(void *p) { free(p); break_optimization();}
__attribute__((noinline))
  void free_bbb(void *p) { free_ccc(p); break_optimization();}
__attribute__((noinline))
  void free_aaa(void *p) { free_bbb(p); break_optimization();}

template<class T>
__attribute__((noinline))
void oob_test(int size, int off) {
  char *p = (char*)malloc_aaa(size);
  // fprintf(stderr, "writing %d byte(s) into [%p,%p) with offset %d\n",
  //        sizeof(T), p, p + size, off);
  asan_write((T*)(p + off));
  free_aaa(p);
}


template<class T>
__attribute__((noinline))
void uaf_test(int size, int off) {
  char *p = (char *)malloc_aaa(size);
  free_aaa(p);
  for (int i = 1; i < 100; i++)
    free_aaa(malloc_aaa(i));
  fprintf(stderr, "writing %ld byte(s) at %p with offset %d\n",
          (long)sizeof(T), p, off);
  asan_write((T*)(p + off));
}

TEST(AddressSanitizer, ADDRESS_SANITIZER_MacroTest) {
  EXPECT_EQ(1, ADDRESS_SANITIZER);
}

TEST(AddressSanitizer, SimpleDeathTest) {
  EXPECT_DEATH(exit(1), "");
}

TEST(AddressSanitizer, VariousMallocsTest) {
  // fprintf(stderr, "malloc:\n");
  int *a = (int*)malloc(100 * sizeof(int));
  a[50] = 0;
  free(a);

  // fprintf(stderr, "realloc:\n");
  int *r = (int*)malloc(10);
  r = (int*)realloc(r, 2000);
  r[1000] = 0;
  free(r);

  // fprintf(stderr, "operator new []\n");
  int *b = new int[100];
  b[50] = 0;
  delete [] b;

  // fprintf(stderr, "operator new\n");
  int *c = new int;
  *c = 0;
  delete c;

#ifndef __APPLE__
  // fprintf(stderr, "posix_memalign\n");
  int *pm;
  int pm_res = posix_memalign((void**)&pm, 4096, 4096);
  EXPECT_EQ(0, pm_res);

  int *ma = (int*)memalign(4096, 4096);
  EXPECT_EQ(0, (uintptr_t)ma % 4096);
  ma[123] = 0;
  free(ma);
#endif  // __APPLE__
}

void NoOpSignalHandler(int) {
  fprintf(stderr, "NoOpSignalHandler (should not happen). Aborting\n");
  abort();
}

void NoOpSigaction(int, siginfo_t *siginfo, void *context) {
  fprintf(stderr, "NoOpSigaction (should not happen). Aborting\n");
  abort();
}

TEST(AddressSanitizer, SignalTest) {
  signal(SIGSEGV, NoOpSignalHandler);
  // If asan did not intercept signal,
  // NoOpSignalHandler will fire later.
}

TEST(AddressSanitizer, SigactionTest) {
  struct sigaction sigact;
  memset(&sigact, 0, sizeof(sigact));
  sigact.sa_sigaction = NoOpSigaction;;
  sigact.sa_flags = SA_SIGINFO;
  sigaction(SIGSEGV, &sigact, 0);
  // If asan did not intercept sigaction,
  // NoOpSigaction will fire later.
}

template<class T>
void OOBTest() {
  char expected_str[100];
  for (int size = sizeof(T); size < 20; size += 5) {
    for (int i = -5; i < 0; i++) {
      const char *str =
          "address located.*%d byte.*to the left";
      sprintf(expected_str, str, abs(i));
      EXPECT_DEATH(oob_test<T>(size, i), expected_str);
    }

    for(int i = 0; i < size - sizeof(T) + 1; i++)
      oob_test<T>(size, i);

    for (int i = size - sizeof(T) + 1; i <= size + 3 * sizeof(T); i++) {
      const char *str =
          "address located.*%d byte.*to the right";
      int off = i >= size ? (i - size) : 0;
      // we don't catch unaligned partially OOB accesses.
      if (i % sizeof(T)) continue;
      sprintf(expected_str, str, off);
      EXPECT_DEATH(oob_test<T>(size, i), expected_str);
    }
  }

  EXPECT_DEATH(oob_test<T>(kLargeMalloc, -1),
          "address located.*1 byte.*to the left");
  EXPECT_DEATH(oob_test<T>(kLargeMalloc, kLargeMalloc),
          "address located.*0 byte.*to the right");
}

TEST(AddressSanitizer, OOB_char) {
  OOBTest<U1>();
}

TEST(AddressSanitizer, OOB_int) {
  OOBTest<U4>();
}

TEST(AddressSanitizer, OOBRightTest) {
  for (size_t access_size = 1; access_size <= 8; access_size *= 2) {
    for (size_t alloc_size = 1; alloc_size <= 8; alloc_size++) {
      for (size_t offset = 0; offset <= 8; offset += access_size) {
        void *p = malloc(alloc_size);
        // allocated: [p, p + alloc_size)
        // accessed:  [p + offset, p + offset + access_size)
        uint8_t *addr = (uint8_t*)p + offset;
        if (offset + access_size <= alloc_size) {
          asan_write_sized_aligned(addr, access_size);
        } else {
          int outside_bytes = offset > alloc_size ? (offset - alloc_size) : 0;
          const char *str =
              "address located.%d *byte.*to the right";
          char expected_str[100];
          sprintf(expected_str, str, outside_bytes);
          EXPECT_DEATH(asan_write_sized_aligned(addr, access_size),
                       expected_str);
        }
        free(p);
      }
    }
  }
}

TEST(AddressSanitizer, UAF_char) {
  EXPECT_DEATH(uaf_test<U1>(1, 0), "AddressSanitizer.*freed");
  EXPECT_DEATH(uaf_test<U1>(10, 0), "AddressSanitizer.*freed");
  EXPECT_DEATH(uaf_test<U1>(10, 10), "AddressSanitizer.*freed");
  EXPECT_DEATH(uaf_test<U1>(kLargeMalloc, 0), "AddressSanitizer.*freed");
  EXPECT_DEATH(uaf_test<U1>(kLargeMalloc, kLargeMalloc / 2),
               "AddressSanitizer.*freed");
}

TEST(AddressSanitizer, IgnoreTest) {
  int *x = new int;
  delete x;
  *x = 0;
}

TEST(AddressSanitizer, OutOfMemoryTest) {
  size_t size = __WORDSIZE == 64 ? (size_t)(1ULL << 40) : (0xf0000000);
  EXPECT_DEATH(printf("%p\n", malloc(size)),
               "ERROR: AddressSanitizer failed to allocate.*main memory");
}

TEST(AddressSanitizer, WildAddressTest) {
  char *c = (char*)0x123;
  EXPECT_DEATH(*c = 0,
               "The failing address is not inside the shadow region");
}

void MallocStress() {
  vector<void *> vec;
  for (size_t i = 0; i < 100000; i++) {
    if ((i % 3) == 0) {
      if (vec.empty()) continue;
      size_t idx = rand() % vec.size();
      void *ptr = vec[idx];
      vec[idx] = vec.back();
      vec.pop_back();
      free_aaa(ptr);
    } else {
      size_t size = rand() % 1000 + 1;
      void *ptr = malloc_aaa(size);
      vec.push_back(ptr);
      for (size_t i = 0; i < size; i++) {
        *((char*)ptr) = 0;
      }
    }
  }
}

TEST(AddressSanitizer, MallocStressTest) {
  MallocStress();
}

TEST(AddressSanitizer, ThreadedMallocStressTest) {
  const int kNumThreads = 4;
  pthread_t t[kNumThreads];
  for (int i = 0; i < kNumThreads; i++) {
    pthread_create(&t[i], 0, (void* (*)(void*))MallocStress, 0);
  }
  for (int i = 0; i < kNumThreads; i++) {
    pthread_join(t[i], 0);
  }
}

TEST(AddressSanitizer, ReallocTest) {
  const int kMinElem = 5;
  int *ptr = (int*)malloc(sizeof(int) * kMinElem);
  ptr[3] = 3;
  for (int i = 0; i < 10000; i++) {
    ptr = (int*)realloc(ptr, (rand() % 1000 + kMinElem) * sizeof(int));
    EXPECT_EQ(3, ptr[3]);
  }
}

void WrongFree() {
  int *x = (int*)malloc(100 * sizeof(int));
  free(x + 1);
}

TEST(AddressSanitizer, DISABLED_WrongFreeTest) {
  WrongFree();
  //EXPECT_DEATH(WrongFree, "attempting free.*not malloc");
}

void DoubleFree() {
  int *x = (int*)malloc(100 * sizeof(int));
  fprintf(stderr, "DoubleFree: x=%p\n", x);
  free(x);
  free(x);
  fprintf(stderr, "should have failed in the second free(%p)\n", x);
  abort();
}

TEST(AddressSanitizer, DoubleFreeTest) {
  EXPECT_DEATH(DoubleFree(), "attempting double-free");
}

template<class T>
__attribute__((noinline))
static T Ident(T t) {
  return t;
}

template<int kSize>
__attribute__((noinline))
void SizedStackTest() {
  char a[kSize];
  char  *A = Ident((char*)&a);
  for (size_t i = 0; i < kSize; i++)
    A[i] = i;
  EXPECT_DEATH(A[-1] = 0, "");
  EXPECT_DEATH(A[-20] = 0, "");
  EXPECT_DEATH(A[-32] = 0, "");
  EXPECT_DEATH(A[kSize] = 0, "");
  EXPECT_DEATH(A[kSize + 1] = 0, "");
  EXPECT_DEATH(A[kSize + 10] = 0, "");
  EXPECT_DEATH(A[kSize + 32] = 0, "");
}

TEST(AddressSanitizer, DISABLED_SimpleStackTest) {
  SizedStackTest<1>();
  SizedStackTest<2>();
  SizedStackTest<3>();
  SizedStackTest<4>();
  SizedStackTest<5>();
  SizedStackTest<6>();
  SizedStackTest<7>();
  SizedStackTest<16>();
  SizedStackTest<25>();
  SizedStackTest<34>();
  SizedStackTest<43>();
  SizedStackTest<51>();
  SizedStackTest<62>();
  SizedStackTest<64>();
  SizedStackTest<128>();
}

__attribute__((noinline))
static void LargeFunction() {
  int *x = new int [100];
  x[0]++;
  x[1]++;
  x[2]++;
  x[3]++;
  x[4]++;
  x[5]++;
  x[6]++;
  x[7]++;
  x[8]++;
  x[9]++;

  x[100]++;

  x[10]++;
  x[11]++;
  x[12]++;
  x[13]++;
  x[14]++;
  x[15]++;
  x[16]++;
  x[17]++;
  x[18]++;
  x[19]++;

  delete x;
}

TEST(AddressSanitizer, DISABLED_LargeFunctionTest) {
  LargeFunction();
}

void *ThreadedTestAlloc(void *a) {
  int **p = (int**)a;
  *p = new int;
  return 0;
}

void *ThreadedTestFree(void *a) {
  int **p = (int**)a;
  delete *p;
  return 0;
}

void *ThreadedTestUse(void *a) {
  int **p = (int**)a;
  **p = 1;
  return 0;
}

void ThreadedTestSpawn() {
  pthread_t t;
  int *x;
  pthread_create(&t, 0, ThreadedTestAlloc, &x);
  pthread_join(t, 0);
  pthread_create(&t, 0, ThreadedTestFree, &x);
  pthread_join(t, 0);
  pthread_create(&t, 0, ThreadedTestUse, &x);
  pthread_join(t, 0);
}

TEST(AddressSanitizer, ThreadedTest) {
  EXPECT_DEATH(ThreadedTestSpawn(),
    "Thread T.*created.*Thread T.*created.*Thread T.*created.*");
}

// ------------------ demo tests; run each one-by-one -------------
// e.g. --gtest_filter=*DemoOOBLeftHigh --gtest_also_run_disabled_tests
TEST(AddressSanitizer, DISABLED_DemoThreadedTest) {
  ThreadedTestSpawn();
}

TEST(AddressSanitizer, DISABLED_DemoUAFLowIn) {
  uaf_test<U1>(10, 0);
}
TEST(AddressSanitizer, DISABLED_DemoUAFLowLeft) {
  uaf_test<U1>(10, -2);
}
TEST(AddressSanitizer, DISABLED_DemoUAFLowRight) {
  uaf_test<U1>(10, 10);
}

TEST(AddressSanitizer, DISABLED_DemoUAFHigh) {
  uaf_test<U1>(kLargeMalloc, 0);
}

TEST(AddressSanitizer, DISABLED_DemoOOBLeftLow) {
  oob_test<U1>(10, -1);
}

TEST(AddressSanitizer, DISABLED_DemoOOBLeftHigh) {
  oob_test<U1>(kLargeMalloc, -1);
}

TEST(AddressSanitizer, DISABLED_DemoOOBRightLow) {
  oob_test<U1>(10, 10);
}

TEST(AddressSanitizer, DISABLED_DemoOOBRightHigh) {
  oob_test<U1>(kLargeMalloc, kLargeMalloc);
}

TEST(AddressSanitizer, DISABLED_DemoOOM) {
  size_t size = __WORDSIZE == 64 ? (size_t)(1ULL << 40) : (0xf0000000);
  printf("%p\n", malloc(size));
}

int main(int argc, char **argv) {
  testing::GTEST_FLAG(death_test_style) = "threadsafe";
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
