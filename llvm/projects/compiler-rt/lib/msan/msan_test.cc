#include "msan_interface.h"
#include "gtest/gtest.h"

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

typedef unsigned char      U1;
typedef unsigned short     U2;
typedef unsigned int       U4;
typedef unsigned long long U8;
typedef   signed char      S1;
typedef   signed short     S2;
typedef   signed int       S4;
typedef   signed long long S8;
#define NOINLINE      __attribute__((noinline))


#define EXPECT_POISONED(action)      \
    do {                        \
      __msan_set_expect_umr(1); \
      action;                   \
      __msan_set_expect_umr(0); \
    } while (0)

static U8 poisoned_array[100];
template<class T>
T *GetPoisoned(int i = 0, T val = 0) {
  T *res = (T*)&poisoned_array[i];
  *res = val;
  __msan_poison(&poisoned_array[i], sizeof(T));
  return res;
}

template<class T> NOINLINE T ReturnPoisoned() { return *GetPoisoned<T>(); }

static volatile S1 v_s1;
static volatile S2 v_s2;
static volatile S4 v_s4;
static volatile S8 v_s8;
static volatile U1 v_u1;
static volatile U2 v_u2;
static volatile U4 v_u4;
static volatile U8 v_u8;
static volatile int g_one = 1;
static volatile int g_zero = 0;

S4 a_s4[100];
S8 a_s8[100];

TEST(MemorySanitizer, NegativeTest1) {
  S4 *x = GetPoisoned<S4>();
  if (g_one)
    *x = 0;
  v_s4 = *x;
}

TEST(MemorySanitizer, PositiveTest1) {
  // Load to store.
  EXPECT_POISONED(v_s1 = *GetPoisoned<S1>());
  EXPECT_POISONED(v_s2 = *GetPoisoned<S2>());
  EXPECT_POISONED(v_s4 = *GetPoisoned<S4>());
  EXPECT_POISONED(v_s8 = *GetPoisoned<S8>());

  // S->S conversions.
  EXPECT_POISONED(v_s2 = *GetPoisoned<S1>());
  EXPECT_POISONED(v_s4 = *GetPoisoned<S1>());
  EXPECT_POISONED(v_s8 = *GetPoisoned<S1>());

  EXPECT_POISONED(v_s1 = *GetPoisoned<S2>());
  EXPECT_POISONED(v_s4 = *GetPoisoned<S2>());
  EXPECT_POISONED(v_s8 = *GetPoisoned<S2>());

  EXPECT_POISONED(v_s1 = *GetPoisoned<S4>());
  EXPECT_POISONED(v_s2 = *GetPoisoned<S4>());
  EXPECT_POISONED(v_s8 = *GetPoisoned<S4>());

  EXPECT_POISONED(v_s1 = *GetPoisoned<S8>());
  EXPECT_POISONED(v_s2 = *GetPoisoned<S8>());
  EXPECT_POISONED(v_s4 = *GetPoisoned<S8>());

  // ZExt
  EXPECT_POISONED(v_s2 = *GetPoisoned<U1>());
  EXPECT_POISONED(v_s4 = *GetPoisoned<U1>());
  EXPECT_POISONED(v_s8 = *GetPoisoned<U1>());
  EXPECT_POISONED(v_s4 = *GetPoisoned<U2>());
  EXPECT_POISONED(v_s8 = *GetPoisoned<U2>());
  EXPECT_POISONED(v_s8 = *GetPoisoned<U4>());

  // Unary ops.
  EXPECT_POISONED(v_s4 = - *GetPoisoned<S4>());

  EXPECT_POISONED(a_s4[g_zero] = 100 / *GetPoisoned<S4>(0, 1));


  a_s4[g_zero] = 1 - *GetPoisoned<S4>();
  a_s4[g_zero] = 1 + *GetPoisoned<S4>();

}

TEST(MemorySanitizer, Phi1) {
  S4 c;
  if (g_one) {
    c = *GetPoisoned<S4>();
  } else {
    __msan_break_optimization(0);
    c = 0;
  }
  EXPECT_POISONED(v_s4 = c);
}

TEST(MemorySanitizer, Phi2) {
  S4 i = *GetPoisoned<S4>();
  S4 n = g_one;
  EXPECT_POISONED(for (; i < g_one; i++););
  EXPECT_POISONED(v_s4 = i);
}

NOINLINE void Arg1ExpectUMR(S4 a1) { EXPECT_POISONED(v_s4 = a1); }
NOINLINE void Arg2ExpectUMR(S4 a1, S4 a2) { EXPECT_POISONED(v_s4 = a2); }
NOINLINE void Arg3ExpectUMR(S1 a1, S4 a2, S8 a3) { EXPECT_POISONED(v_s8 = a3); }

TEST(MemorySanitizer, ArgTest) {
  Arg1ExpectUMR(*GetPoisoned<S4>());
  Arg2ExpectUMR(0, *GetPoisoned<S4>());
  Arg3ExpectUMR(0, 1, *GetPoisoned<S8>());
}


TEST(MemorySanitizer, CallAndRet) {
  if (!__msan_has_dynamic_component()) return;
  ReturnPoisoned<S1>();
  ReturnPoisoned<S2>();
  ReturnPoisoned<S4>();
  ReturnPoisoned<S8>();

  EXPECT_POISONED(v_s1 = ReturnPoisoned<S1>());
  EXPECT_POISONED(v_s2 = ReturnPoisoned<S2>());
  EXPECT_POISONED(v_s4 = ReturnPoisoned<S4>());
  EXPECT_POISONED(v_s8 = ReturnPoisoned<S8>());
}

TEST(MemorySanitizer, Malloc) {
  S4 *x = (int*)malloc(sizeof(S4));
  EXPECT_POISONED(v_s4 = *x);
  free(x);
}

TEST(MemorySanitizer, Realloc) {
  S4 *x = (int*)realloc(0, sizeof(S4));
  EXPECT_POISONED(v_s4 = x[0]);
  x[0] = 1;
  x = (int*)realloc(x, 2 * sizeof(S4));
  v_s4 = x[0];  // Ok, was inited before.
  EXPECT_POISONED(v_s4 = x[1]);
  x = (int*)realloc(x, 3 * sizeof(S4));
  EXPECT_POISONED(v_s4 = x[2]);
  EXPECT_POISONED(v_s4 = x[1]);
  free(x);
}

TEST(MemorySanitizer, Calloc) {
  S4 *x = (int*)calloc(1, sizeof(S4));
  v_s4 = *x;  // Should not be poisoned.
  // EXPECT_EQ(0, *x);
  free(x);
}

TEST(MemorySanitizer, AndOr) {
  U4 *p = GetPoisoned<U4>();
  // We poison two bytes in the midle of a 4-byte word to make the test
  // correct regardless of endianness.
  ((U1*)p)[1] = 0;
  ((U1*)p)[2] = 0xff;
  v_u4 = *p & 0x00ffff00;
  v_u4 = *p & 0x00ff0000;
  v_u4 = *p & 0x0000ff00;
  EXPECT_POISONED(v_u4 = *p & 0xff000000);
  EXPECT_POISONED(v_u4 = *p & 0x000000ff);
  EXPECT_POISONED(v_u4 = *p & 0x0000ffff);
  EXPECT_POISONED(v_u4 = *p & 0xffff0000);

  v_u4 = *p | 0xff0000ff;
  v_u4 = *p | 0xff00ffff;
  v_u4 = *p | 0xffff00ff;
  EXPECT_POISONED(v_u4 = *p | 0xff000000);
  EXPECT_POISONED(v_u4 = *p | 0x000000ff);
  EXPECT_POISONED(v_u4 = *p | 0x0000ffff);
  EXPECT_POISONED(v_u4 = *p | 0xffff0000);

  EXPECT_POISONED(v_u4 = *GetPoisoned<bool>() & *GetPoisoned<bool>());
}

TEST(MemorySanitizer, Shift) {
  U4 *up = GetPoisoned<U4>();
  ((U1*)up)[0] = 0;
  ((U1*)up)[3] = 0xff;
  v_u4 = *up >> 30;
  v_u4 = *up >> 24;
  EXPECT_POISONED(v_u4 = *up >> 23);
  EXPECT_POISONED(v_u4 = *up >> 10);

  v_u4 = *up << 30;
  v_u4 = *up << 24;
  EXPECT_POISONED(v_u4 = *up << 23);
  EXPECT_POISONED(v_u4 = *up << 10);

  S4 *sp = (S4*)up;
  v_s4 = *sp >> 30;
  v_s4 = *sp >> 24;
  EXPECT_POISONED(v_s4 = *sp >> 23);
  EXPECT_POISONED(v_s4 = *sp >> 10);

  sp = GetPoisoned<S4>();
  ((S1*)sp)[1] = 0;
  ((S1*)sp)[2] = 0;
  EXPECT_POISONED(v_s4 = *sp >> 31);

  v_s4 = 100;
  EXPECT_POISONED(v_s4 = v_s4 >> *GetPoisoned<S4>());
  v_u4 = 100;
  EXPECT_POISONED(v_u4 = v_u4 >> *GetPoisoned<S4>());
  v_u4 = 100;
  EXPECT_POISONED(v_u4 = v_u4 << *GetPoisoned<S4>());
}

NOINLINE void StackTestFunc() {
  S4 p4;
  S4 ok4 = 1;
  S2 p2;
  S2 ok2 = 1;
  S1 p1;
  S1 ok1 = 1;
  __msan_break_optimization(&p4);
  __msan_break_optimization(&ok4);
  __msan_break_optimization(&p2);
  __msan_break_optimization(&ok2);
  __msan_break_optimization(&p1);
  __msan_break_optimization(&ok1);

  EXPECT_POISONED(v_s4 = p4);
  EXPECT_POISONED(v_s2 = p2);
  EXPECT_POISONED(v_s1 = p1);
  v_s1 = ok1;
  v_s2 = ok2;
  v_s4 = ok4;
}

TEST(MemorySanitizer, DISABLED_StackTest) {
  if (!__msan_has_dynamic_component()) return;
  StackTestFunc();
}

template<class T>
void TestFloatingPoint() {
  static volatile T v;
  static T g[100];
  __msan_break_optimization(&g);
  T *x = GetPoisoned<T>();
  T *y = GetPoisoned<T>(1);
  EXPECT_POISONED(v = *x);
  g[0] = *x;
  g[1] = *x + *y;
  g[2] = *x - *y;
  g[3] = *x * *y;
}

TEST(MemorySanitizer, FloatingPointTest) {
  TestFloatingPoint<float>();
  TestFloatingPoint<double>();
}

TEST(MemorySanitizer, DynMem) {
  S4 x = 0;
  S4 *y = GetPoisoned<S4>();
  memcpy(y, &x, g_one * sizeof(S4));
  v_s4 = *y;
}

static char *DynRetTestStr;

TEST(MemorySanitizer, DynRet) {
  if (!__msan_has_dynamic_component()) return;
  ReturnPoisoned<S8>();
  v_s4 = clearenv();
}


TEST(MemorySanitizer, DynRet1) {
  if (!__msan_has_dynamic_component()) return;
  ReturnPoisoned<S8>();
}

struct LargeStruct {
  S4 x[10];
};

NOINLINE
LargeStruct LargeRetTest() {
  LargeStruct res;
  res.x[0] = *GetPoisoned<S4>();
  res.x[1] = *GetPoisoned<S4>();
  res.x[2] = *GetPoisoned<S4>();
  res.x[3] = *GetPoisoned<S4>();
  res.x[4] = *GetPoisoned<S4>();
  res.x[5] = *GetPoisoned<S4>();
  res.x[6] = *GetPoisoned<S4>();
  res.x[7] = *GetPoisoned<S4>();
  res.x[8] = *GetPoisoned<S4>();
  res.x[9] = *GetPoisoned<S4>();
  return res;
}

TEST(MemorySanitizer, LargeRet) {
  LargeStruct a = LargeRetTest();
  EXPECT_POISONED(v_s4 = a.x[0]);
  EXPECT_POISONED(v_s4 = a.x[9]);
}

TEST(MemorySanitizer, fread) {
  char *x = new char[32];
  FILE *f = fopen("/proc/self/stat", "r");
  assert(f);
  fread(x, 1, 32, f);
  v_s1 = x[0];
  v_s1 = x[16];
  v_s1 = x[31];
  fclose(f);
  delete x;
}

extern "C" {
NOINLINE void ZZZZZZZZZZZZZZZ() {
  __msan_break_optimization(0);

  // v_s1 = ReturnPoisoned<S1>();
  // a_s8[g_zero] = *GetPoisoned<S8>() - 1;
  // v_s4 = a_s4[g_zero];
  __msan_break_optimization(0);
}
}

TEST(MemorySanitizer, ZZZTest) {
  ZZZZZZZZZZZZZZZ();
}

int main(int argc, char **argv) {
  __msan_set_exit_code(33);
  __msan_set_poison_in_malloc(1);
  testing::InitGoogleTest(&argc, argv);
  int res = RUN_ALL_TESTS();
  return res;
}
