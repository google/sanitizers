#include "msan_interface.h"
#include "msandr_test_so.h"
#include "gtest/gtest.h"

#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <assert.h>
#include <wchar.h>

#include <unistd.h>
#include <limits.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

typedef unsigned char      U1;
typedef unsigned short     U2;
typedef unsigned int       U4;
typedef unsigned long long U8;
typedef   signed char      S1;
typedef   signed short     S2;
typedef   signed int       S4;
typedef   signed long long S8;
#define NOINLINE      __attribute__((noinline))
#define INLINE      __attribute__((always_inline))


#define EXPECT_POISONED(action) \
    do {                        \
      __msan_set_expect_umr(1); \
      action;                   \
      __msan_set_expect_umr(0); \
    } while (0)

#define EXPECT_POISONED_O(action, origin) \
    do {                                            \
      __msan_set_expect_umr(1);                     \
      action;                                       \
      __msan_set_expect_umr(0);                     \
      EXPECT_EQ(origin, __msan_get_origin_tls());   \
    } while (0)

#define EXPECT_POISONED_S(action, stack_origin) \
    do {                                            \
      __msan_set_expect_umr(1);                     \
      action;                                       \
      __msan_set_expect_umr(0);                     \
      u32 id = __msan_get_origin_tls();             \
      const char *str = __msan_get_origin_descr_if_stack(id); \
      if (!str || strcmp(str, stack_origin)) {      \
        fprintf(stderr, "EXPECT_POISONED_S: id=%u %s, %s", \
                id, stack_origin, str);  \
        EXPECT_EQ(1, 0);                            \
      }                                             \
    } while (0)


static U8 poisoned_array[100];
template<class T>
T *GetPoisoned(int i = 0, T val = 0) {
  T *res = (T*)&poisoned_array[i];
  *res = val;
  __msan_poison(&poisoned_array[i], sizeof(T));
  return res;
}

template<class T>
T *GetPoisonedO(int i, u32 origin, T val = 0) {
  T *res = (T*)&poisoned_array[i];
  *res = val;
  __msan_poison(&poisoned_array[i], sizeof(T));
  __msan_set_origin(&poisoned_array[i], sizeof(T), origin);
  return res;
}

static bool TrackingOrigins() {
  long x;
  __msan_set_origin(&x, sizeof(x), 0x1234);
  u32 origin = __msan_get_origin(&x);
  __msan_set_origin(&x, sizeof(x), 0);
  return origin == 0x1234;
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
static void* volatile v_p;
static volatile double v_d;
static volatile int g_one = 1;
static volatile int g_zero = 0;
static volatile int g_0 = 0;
static volatile int g_1 = 1;

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
  v_s4 = x[0];  // Ok, was inited before.
  EXPECT_POISONED(v_s4 = x[2]);
  EXPECT_POISONED(v_s4 = x[1]);
  x[2] = 1;  // Init this here. Check that after realloc it is poisoned again.
  x = (int*)realloc(x, 2 * sizeof(S4));
  v_s4 = x[0];  // Ok, was inited before.
  EXPECT_POISONED(v_s4 = x[1]);
  x = (int*)realloc(x, 3 * sizeof(S4));
  EXPECT_POISONED(v_s4 = x[1]);
  EXPECT_POISONED(v_s4 = x[2]);
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

template<class T>
static void testNot(T value, T shadow) {
  __msan_partial_poison(&value, &shadow, sizeof(T));
  volatile bool v_T = !value;
}

TEST(MemorySanitizer, Not) {
  testNot<U4>(0x0, 0x0);
  testNot<U4>(0xFFFFFFFF, 0x0);
  EXPECT_POISONED(testNot<U4>(0xFFFFFFFF, 0xFFFFFFFF));
  testNot<U4>(0xFF000000, 0x0FFFFFFF);
  testNot<U4>(0xFF000000, 0x00FFFFFF);
  testNot<U4>(0xFF000000, 0x0000FFFF);
  testNot<U4>(0xFF000000, 0x00000000);
  EXPECT_POISONED(testNot<U4>(0xFF000000, 0xFF000000));
  testNot<U4>(0xFF800000, 0xFF000000);
  EXPECT_POISONED(testNot<U4>(0x00008000, 0x00008000));

  testNot<U1>(0x0, 0x0);
  testNot<U1>(0xFF, 0xFE);
  testNot<U1>(0xFF, 0x0);
  EXPECT_POISONED(testNot<U1>(0xFF, 0xFF));

  EXPECT_POISONED(testNot<void*>((void*)0xFFFFFF, (void*)(-1)));
  testNot<void*>((void*)0xFFFFFF, (void*)(-2));
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

NOINLINE static int GetPoisonedZero() {
  int *zero = new int;
  *zero = 0;
  __msan_poison(zero, sizeof(int));
  int res = *zero;
  delete zero;
  return res;
}

TEST(MemorySanitizer, LoadFromDirtyAddress) {
  int *a = new int;
  *a = 0;
  EXPECT_POISONED(__msan_break_optimization((void*)a[GetPoisonedZero()]));
  delete a;
}

TEST(MemorySanitizer, StoreToDirtyAddress) {
  int *a = new int;
  EXPECT_POISONED(a[GetPoisonedZero()] = 0);
  __msan_break_optimization(a);
  delete a;
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

TEST(MemorySanitizer, StackTest) {
  StackTestFunc();
}

NOINLINE void StackStressFunc() {
  int foo[10000];
  __msan_break_optimization(foo);
}

TEST(MemorySanitizer, DISABLED_StackStressTest) {
  for (int i = 0; i < 1000000; i++)
    StackStressFunc();
}

template<class T>
void TestFloatingPoint() {
  static volatile T v;
  static T g[100];
  __msan_break_optimization(&g);
  T *x = GetPoisoned<T>();
  T *y = GetPoisoned<T>(1);
  EXPECT_POISONED(v = *x);
  EXPECT_POISONED(v_s8 = *x);
  EXPECT_POISONED(v_s4 = *x);
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

TEST(MemorySanitizer, read) {
  char *x = new char[32];
  int fd = open("/proc/self/stat", O_RDONLY);
  assert(fd > 0);
  int sz = read(fd, x, 32);
  assert(sz == 32);
  v_s1 = x[0];
  v_s1 = x[16];
  v_s1 = x[31];
  close(fd);
  delete x;
}

TEST(MemorySanitizer, stat) {
  struct stat* st = new struct stat;
  int res = stat("/proc/self/stat", st);
  assert(!res);
  v_u8 = st->st_dev;
  v_u8 = st->st_mode;
  v_u8 = st->st_size;
}

TEST(MemorySanitizer, pipe) {
  int* pipefd = new int[2];
  int res = pipe(pipefd);
  assert(!res);
  v_u8 = pipefd[0];
  v_u8 = pipefd[1];
  close(pipefd[0]);
  close(pipefd[1]);
}

TEST(MemorySanitizer, getcwd) {
  char path[PATH_MAX + 1];
  char* res = getcwd(path, sizeof(path));
  assert(res);
  v_s1 = path[0];
}

TEST(MemorySanitizer, realpath) {
  const char* relpath = ".";
  char path[PATH_MAX + 1];
  char* res = realpath(relpath, path);
  assert(res);
  v_s1 = path[0];
}

TEST(MemorySanitizer, memcpy) {
  char* x = new char[2];
  char* y = new char[2];
  x[0] = 1;
  x[1] = *GetPoisoned<char>();
  memcpy(y, x, 2);
  v_s4 = y[0];
  EXPECT_POISONED(v_s4 = y[1]);
}

TEST(MemorySanitizer, memmove) {
  char* x = new char[2];
  char* y = new char[2];
  x[0] = 1;
  x[1] = *GetPoisoned<char>();
  memmove(y, x, 2);
  v_s4 = y[0];
  EXPECT_POISONED(v_s4 = y[1]);
}

TEST(MemorySanitizer, strcpy) {
  char* x = new char[3];
  char* y = new char[3];
  x[0] = 'a'; x[1] = *GetPoisoned<char>(1, 1); x[2] = 0;
  strcpy(y, x);
  v_s4 = y[0];
  EXPECT_POISONED(v_s4 = y[1]);
  v_s4 = y[2];
}

TEST(MemorySanitizer, strncpy) {
  char* x = new char[3];
  char* y = new char[3];
  x[0] = 'a'; x[1] = *GetPoisoned<char>(1, 1); x[2] = 0;
  strncpy(y, x, 2);
  v_s4 = y[0];
  EXPECT_POISONED(v_s4 = y[1]);
  EXPECT_POISONED(v_s4 = y[2]);
}

TEST(MemorySanitizer, strtol) {
  char *e;
  assert(1 == strtol("1", &e, 10));
  v_s8 = (S8) e;
}

TEST(MemorySanitizer, strtoll) {
  char *e;
  assert(1 == strtoll("1", &e, 10));
  v_s8 = (S8) e;
}

TEST(MemorySanitizer, sprintf) {
  char buff[10];
  __msan_break_optimization(buff);
  EXPECT_POISONED(v_s1 = buff[0]);
  int res = sprintf(buff, "%d", 1234567);
  assert(res == 7);
  assert(buff[0] == '1');
  assert(buff[1] == '2');
  assert(buff[2] == '3');
  assert(buff[6] == '7');
  assert(buff[7] == 0);
  EXPECT_POISONED(v_s1 = buff[8]);
}

TEST(MemorySanitizer, snprintf) {
  char buff[10];
  __msan_break_optimization(buff);
  EXPECT_POISONED(v_s1 = buff[0]);
  int res = snprintf(buff, 9, "%d", 1234567);
  assert(res == 7);
  assert(buff[0] == '1');
  assert(buff[1] == '2');
  assert(buff[2] == '3');
  assert(buff[6] == '7');
  assert(buff[7] == 0);
  EXPECT_POISONED(v_s1 = buff[8]);
}

TEST(MemorySanitizer, swprintf) {
  wchar_t buff[10];
  assert(sizeof(wchar_t) == 4);
  __msan_break_optimization(buff);
  EXPECT_POISONED(v_s1 = buff[0]);
  int res = swprintf(buff, 9, L"%d", 1234567);
  assert(res == 7);
  assert(buff[0] == '1');
  assert(buff[1] == '2');
  assert(buff[2] == '3');
  assert(buff[6] == '7');
  assert(buff[7] == 0);
  EXPECT_POISONED(v_s4 = buff[8]);
}

TEST(MemorySanitizer, gettimeofday) {
  struct timeval tv;
  struct timezone tz;
  __msan_break_optimization(&tv);
  __msan_break_optimization(&tz);
  assert(sizeof(tv) == 16);
  assert(sizeof(tz) == 8);
  EXPECT_POISONED(v_s8 = tv.tv_sec);
  EXPECT_POISONED(v_s8 = tv.tv_usec);
  EXPECT_POISONED(v_s4 = tz.tz_minuteswest);
  EXPECT_POISONED(v_s4 = tz.tz_dsttime);
  assert(0 == gettimeofday(&tv, &tz));
  v_s8 = tv.tv_sec;
  v_s8 = tv.tv_usec;
  v_s4 = tz.tz_minuteswest;
  v_s4 = tz.tz_dsttime;
}

// FIXME: enable and add ecvt.
// FIXME: check why msandr does nt handle fcvt.
TEST(MemorySanitizer, fcvt) {
  int a, b;
  __msan_break_optimization(&a);
  __msan_break_optimization(&b);
  EXPECT_POISONED(v_s4 = a);
  EXPECT_POISONED(v_s4 = b);
  char *str = fcvt(12345.6789, 10, &a, &b);
  v_s4 = a;
  v_s4 = b;
}

TEST(MemorySanitizer, LoadUnpoisoned) {
  S8 s = *GetPoisoned<S8>();
  EXPECT_POISONED(v_s8 = s);
  S8 safe = *GetPoisoned<S8>();
  __msan_load_unpoisoned(&s, sizeof(s), &safe);
  v_s8 = safe;
}

struct StructWithDtor {
  ~StructWithDtor();
};

NOINLINE StructWithDtor::~StructWithDtor() {
  __msan_break_optimization(0);
}

NOINLINE void ExpectGood(int a) { v_s4 = a; }
NOINLINE void ExpectPoisoned(int a) {
  EXPECT_POISONED(v_s4 = a);
}

// FIXME: start compiling the test w/o -fno-exceptions
TEST(MemorySanitizer, Invoke) {
  StructWithDtor s; // Will cause the calls to become invokes.
  ExpectGood(0);
  ExpectPoisoned(*GetPoisoned<int>());
  ExpectGood(0);
  ExpectPoisoned(*GetPoisoned<int>());
}

TEST(MemorySanitizer, ptrtoint) {
  // Test that shadow is propagated through pointer-to-integer conversion.
  void* p = (void*)0xABCD;
  __msan_poison(((char*)&p) + 1, sizeof(p));
  v_u1 = (((uptr)p) & 0xFF) == 0;

  void* q = (void*)0xABCD;
  __msan_poison(&q, sizeof(q) - 1);
  EXPECT_POISONED(v_u1 = (((uptr)q) & 0xFF) == 0);
}

static void vaargsfn2(int guard, ...) {
  va_list vl;
  va_start(vl, guard);
  v_s4 = va_arg(vl, int);
  v_s4 = va_arg(vl, int);
  v_s4 = va_arg(vl, int);
  EXPECT_POISONED(v_d = va_arg(vl, double));
  va_end(vl);
}

static void vaargsfn(int guard, ...) {
  va_list vl;
  va_start(vl, guard);
  v_s4 = va_arg(vl, int);
  EXPECT_POISONED(v_s4 = va_arg(vl, int));
  // The following call will overwrite __msan_param_tls.
  // Checks after it test that arg shadow was somehow saved across the call.
  vaargsfn2(1, 2, 3, 4, *GetPoisoned<double>());
  v_s4 = va_arg(vl, int);
  EXPECT_POISONED(v_s4 = va_arg(vl, int));
  va_end(vl);
}

TEST(MemorySanitizer, VAArgTest) {
  int* x = GetPoisoned<int>();
  int* y = GetPoisoned<int>(4);
  vaargsfn(1, 13, *x, 42, *y);
}

static void vaargsfn_many(int guard, ...) {
  va_list vl;
  va_start(vl, guard);
  v_s4 = va_arg(vl, int);
  EXPECT_POISONED(v_s4 = va_arg(vl, int));
  v_s4 = va_arg(vl, int);
  v_s4 = va_arg(vl, int);
  v_s4 = va_arg(vl, int);
  v_s4 = va_arg(vl, int);
  v_s4 = va_arg(vl, int);
  v_s4 = va_arg(vl, int);
  v_s4 = va_arg(vl, int);
  EXPECT_POISONED(v_s4 = va_arg(vl, int));
  va_end(vl);
}

TEST(MemorySanitizer, VAArgManyTest) {
  int* x = GetPoisoned<int>();
  int* y = GetPoisoned<int>(4);
  vaargsfn_many(1, 2, *x, 3, 4, 5, 6, 7, 8, 9, *y);
}

static void vaargsfn_pass2(va_list vl) {
  v_s4 = va_arg(vl, int);
  v_s4 = va_arg(vl, int);
  EXPECT_POISONED(v_s4 = va_arg(vl, int));
}

static void vaargsfn_pass(int guard, ...) {
  va_list vl;
  va_start(vl, guard);
  EXPECT_POISONED(v_s4 = va_arg(vl, int));
  vaargsfn_pass2(vl);
  va_end(vl);
}

TEST(MemorySanitizer, VAArgPass) {
  int* x = GetPoisoned<int>();
  int* y = GetPoisoned<int>(4);
  vaargsfn_pass(1, *x, 2, 3, *y);
}

static void vaargsfn_copy2(va_list vl) {
  v_s4 = va_arg(vl, int);
  EXPECT_POISONED(v_s4 = va_arg(vl, int));
}

static void vaargsfn_copy(int guard, ...) {
  va_list vl;
  va_start(vl, guard);
  v_s4 = va_arg(vl, int);
  EXPECT_POISONED(v_s4 = va_arg(vl, int));
  va_list vl2;
  va_copy(vl2, vl);
  vaargsfn_copy2(vl2);
  v_s4 = va_arg(vl, int);
  EXPECT_POISONED(v_s4 = va_arg(vl, int));
  va_end(vl);
}

TEST(MemorySanitizer, VAArgCopy) {
  int* x = GetPoisoned<int>();
  int* y = GetPoisoned<int>(4);
  vaargsfn_copy(1, 2, *x, 3, *y);
}

static void vaargsfn_ptr(int guard, ...) {
  va_list vl;
  va_start(vl, guard);
  v_p = va_arg(vl, int*);
  EXPECT_POISONED(v_p = va_arg(vl, int*));
  v_p = va_arg(vl, int*);
  EXPECT_POISONED(v_p = va_arg(vl, double*));
  va_end(vl);
}

TEST(MemorySanitizer, VAArgPtr) {
  int** x = GetPoisoned<int*>();
  double** y = GetPoisoned<double*>(8);
  int z;
  vaargsfn_ptr(1, &z, *x, &z, *y);
}

static void vaargsfn_overflow(int guard, ...) {
  va_list vl;
  va_start(vl, guard);
  v_s4 = va_arg(vl, int);
  v_s4 = va_arg(vl, int);
  EXPECT_POISONED(v_s4 = va_arg(vl, int));
  v_s4 = va_arg(vl, int);
  v_s4 = va_arg(vl, int);
  v_s4 = va_arg(vl, int);

  v_d = va_arg(vl, double);
  v_d = va_arg(vl, double);
  v_d = va_arg(vl, double);
  EXPECT_POISONED(v_d = va_arg(vl, double));
  v_d = va_arg(vl, double);
  EXPECT_POISONED(v_p = va_arg(vl, int*));
  v_d = va_arg(vl, double);
  v_d = va_arg(vl, double);

  EXPECT_POISONED(v_s4 = va_arg(vl, int));
  EXPECT_POISONED(v_d = va_arg(vl, double));
  EXPECT_POISONED(v_p = va_arg(vl, int*));

  v_s4 = va_arg(vl, int);
  v_d = va_arg(vl, double);
  v_p = va_arg(vl, int*);

  EXPECT_POISONED(v_s4 = va_arg(vl, int));
  EXPECT_POISONED(v_d = va_arg(vl, double));
  EXPECT_POISONED(v_p = va_arg(vl, int*));

  va_end(vl);
}

TEST(MemorySanitizer, VAArgOverflow) {
  int* x = GetPoisoned<int>();
  double* y = GetPoisoned<double>(8);
  int** p = GetPoisoned<int*>(16);
  int z;
  vaargsfn_overflow(1,
      1, 2, *x, 4, 5, 6,
      1.1, 2.2, 3.3, *y, 5.5, *p, 7.7, 8.8,
      // the following args will overflow for sure
      *x, *y, *p,
      7, 9.9, &z,
      *x, *y, *p);
}

static void vaargsfn_tlsoverwrite2(int guard, ...) {
  va_list vl;
  va_start(vl, guard);
  v_s4 = va_arg(vl, int);
  va_end(vl);
}

static void vaargsfn_tlsoverwrite(int guard, ...) {
  // This call will overwrite TLS contents unless it's backed up somewhere.
  vaargsfn_tlsoverwrite2(2, 42);
  va_list vl;
  va_start(vl, guard);
  EXPECT_POISONED(v_s4 = va_arg(vl, int));
  va_end(vl);
}

TEST(MemorySanitizer, VAArgTLSOverwrite) {
  int* x = GetPoisoned<int>();
  vaargsfn_tlsoverwrite(1, *x);
}

struct StructByVal {
  int a, b, c, d, e, f;
};

NOINLINE void StructByValTestFunc(struct StructByVal s) {
  v_s4 = s.a;
  EXPECT_POISONED(v_s4 = s.b);
  v_s4 = s.c;
  EXPECT_POISONED(v_s4 = s.d);
  v_s4 = s.e;
  EXPECT_POISONED(v_s4 = s.f);
}

NOINLINE void StructByValTestFunc1(struct StructByVal s) {
  StructByValTestFunc(s);
}

NOINLINE void StructByValTestFunc2(int z, struct StructByVal s) {
  StructByValTestFunc(s);
}

TEST(MemorySanitizer, StructByVal) {
  // Large aggregates are passed as "byval" pointer argument in LLVM.
  struct StructByVal s;
  s.a = 1;
  s.b = *GetPoisoned<int>();
  s.c = 2;
  s.d = *GetPoisoned<int>();
  s.e = 3;
  s.f = *GetPoisoned<int>();
  StructByValTestFunc(s);
  StructByValTestFunc1(s);
  StructByValTestFunc2(0, s);
}

extern "C" {
NOINLINE void ZZZZZZZZZZZZZZ() {
  __msan_break_optimization(0);

  // v_s1 = ReturnPoisoned<S1>();
  // a_s8[g_zero] = *GetPoisoned<S8>() - 1;
  // v_s4 = a_s4[g_zero];
  __msan_break_optimization(0);
}
}

TEST(MemorySanitizer, ZZZTest) {
  ZZZZZZZZZZZZZZ();
}

TEST(MemorySanitizerDr, StoreInDSOTest) {
  char* s = new char[10];
  dso_memfill(s, 9);
  v_s1 = s[5];
  EXPECT_POISONED(v_s1 = s[9]);
}

int return_poisoned_int() {
  return ReturnPoisoned<U8>();
}

TEST(MemorySanitizerDr, ReturnFromDSOTest) {
  v_u8 = dso_callfn(return_poisoned_int);
}

NOINLINE int TrashParamTLS(long long x, long long y, long long z) {
  EXPECT_POISONED(v_s8 = x);
  EXPECT_POISONED(v_s8 = y);
  EXPECT_POISONED(v_s8 = z);
  return 0;
}

static int CheckParamTLS(long long x, long long y, long long z) {
  v_s8 = x;
  v_s8 = y;
  v_s8 = z;
  return 0;
}

TEST(MemorySanitizerDr, CallFromDSOTest) {
  S8* x = GetPoisoned<S8>();
  S8* y = GetPoisoned<S8>();
  S8* z = GetPoisoned<S8>();
  v_s4 = TrashParamTLS(*x, *y, *z);
  v_u8 = dso_callfn1(CheckParamTLS);
}

static void StackStoreInDSOFn(int* x, int* y) {
  v_s4 = *x;
  v_s4 = *y;
}

TEST(MemorySanitizerDr, StackStoreInDSOTest) {
  dso_stack_store(StackStoreInDSOFn, 1);
}

TEST(MemorySanitizerOrigins, SetGet) {
  EXPECT_EQ(TrackingOrigins(), __msan_track_origins);
  if (!TrackingOrigins()) return;
  int x;
  __msan_set_origin(&x, sizeof(x), 1234);
  EXPECT_EQ(1234, __msan_get_origin(&x));
  __msan_set_origin(&x, sizeof(x), 5678);
  EXPECT_EQ(5678, __msan_get_origin(&x));
  __msan_set_origin(&x, sizeof(x), 0);
  EXPECT_EQ(0, __msan_get_origin(&x));
}

template<class T, class BinaryOp>
INLINE
void BinaryOpOriginTest(BinaryOp op) {
  u32 ox = rand();
  u32 oy = rand();
  T *x = GetPoisonedO<T>(0, ox, 0);
  T *y = GetPoisonedO<T>(1, oy, 0);
  T *z = GetPoisonedO<T>(2, 0, 0);

  *z = op(*x, *y);
  u32 origin = __msan_get_origin(z);
  EXPECT_POISONED_O(v_s8 = *z, origin);
  EXPECT_EQ(true, origin == ox || origin == oy);

  // y is poisoned, x is not.
  *x = 10101;
  *y = *GetPoisonedO<T>(1, oy);
  __msan_break_optimization(x);
  __msan_set_origin(z, sizeof(*z), 0);
  *z = op(*x, *y);
  EXPECT_POISONED_O(v_s8 = *z, oy);
  EXPECT_EQ(__msan_get_origin(z), oy);

  // x is poisoned, y is not.
  *x = *GetPoisonedO<T>(0, ox);
  *y = 10101010;
  __msan_break_optimization(y);
  __msan_set_origin(z, sizeof(*z), 0);
  *z = op(*x, *y);
  EXPECT_POISONED_O(v_s8 = *z, ox);
  EXPECT_EQ(__msan_get_origin(z), ox);
}

template<class T> INLINE T XOR(const T &a, const T&b) { return a ^ b; }
template<class T> INLINE T ADD(const T &a, const T&b) { return a + b; }
template<class T> INLINE T SUB(const T &a, const T&b) { return a - b; }
template<class T> INLINE T MUL(const T &a, const T&b) { return a * b; }
template<class T> INLINE T AND(const T &a, const T&b) { return a & b; }
template<class T> INLINE T OR (const T &a, const T&b) { return a | b; }

TEST(MemorySanitizerOrigins, BinaryOp) {
  if (!TrackingOrigins()) return;
  BinaryOpOriginTest<S8>(XOR<S8>);
  BinaryOpOriginTest<U8>(ADD<U8>);
  BinaryOpOriginTest<S4>(SUB<S4>);
  BinaryOpOriginTest<S4>(MUL<S4>);
  BinaryOpOriginTest<U4>(OR<U4>);
  BinaryOpOriginTest<U4>(AND<U4>);
  BinaryOpOriginTest<double>(ADD<U4>);
  BinaryOpOriginTest<float>(ADD<S4>);
  BinaryOpOriginTest<double>(ADD<double>);
  BinaryOpOriginTest<float>(ADD<double>);
}

TEST(MemorySanitizerOrigins, Unary) {
  if (!TrackingOrigins()) return;
  EXPECT_POISONED_O(v_s8 = *GetPoisonedO<S8>(0, __LINE__), __LINE__);
  EXPECT_POISONED_O(v_s4 = *GetPoisonedO<S8>(0, __LINE__), __LINE__);
  EXPECT_POISONED_O(v_s2 = *GetPoisonedO<S8>(0, __LINE__), __LINE__);
  EXPECT_POISONED_O(v_s1 = *GetPoisonedO<S8>(0, __LINE__), __LINE__);

  EXPECT_POISONED_O(v_s8 = *GetPoisonedO<S4>(0, __LINE__), __LINE__);
  EXPECT_POISONED_O(v_s4 = *GetPoisonedO<S4>(0, __LINE__), __LINE__);
  EXPECT_POISONED_O(v_s2 = *GetPoisonedO<S4>(0, __LINE__), __LINE__);
  EXPECT_POISONED_O(v_s1 = *GetPoisonedO<S4>(0, __LINE__), __LINE__);

  EXPECT_POISONED_O(v_s8 = *GetPoisonedO<U4>(0, __LINE__), __LINE__);
  EXPECT_POISONED_O(v_s4 = *GetPoisonedO<U4>(0, __LINE__), __LINE__);
  EXPECT_POISONED_O(v_s2 = *GetPoisonedO<U4>(0, __LINE__), __LINE__);
  EXPECT_POISONED_O(v_s1 = *GetPoisonedO<U4>(0, __LINE__), __LINE__);

  EXPECT_POISONED_O(v_u8 = *GetPoisonedO<S4>(0, __LINE__), __LINE__);
  EXPECT_POISONED_O(v_u4 = *GetPoisonedO<S4>(0, __LINE__), __LINE__);
  EXPECT_POISONED_O(v_u2 = *GetPoisonedO<S4>(0, __LINE__), __LINE__);
  EXPECT_POISONED_O(v_u1 = *GetPoisonedO<S4>(0, __LINE__), __LINE__);

  EXPECT_POISONED_O(v_p = (void*)*GetPoisonedO<S8>(0, __LINE__), __LINE__);
  EXPECT_POISONED_O(v_u8 = (U8)*GetPoisonedO<void*>(0, __LINE__), __LINE__);
}

TEST(MemorySanitizerOrigins, EQ) {
  if (!TrackingOrigins()) return;
  EXPECT_POISONED_O(v_u1 = *GetPoisonedO<S4>(0, __LINE__) <= 11, __LINE__);
  EXPECT_POISONED_O(v_u1 = *GetPoisonedO<S4>(0, __LINE__) == 11, __LINE__);
  EXPECT_POISONED_O(v_u1 = *GetPoisonedO<float>(0, __LINE__) == 1.1, __LINE__);
}

TEST(MemorySanitizerOrigins, DIV) {
  if (!TrackingOrigins()) return;
  EXPECT_POISONED_O(v_u8 = *GetPoisonedO<U8>(0, __LINE__) / 100, __LINE__);
  EXPECT_POISONED_O(v_s4 = 100 / *GetPoisonedO<S4>(0, __LINE__, 1), __LINE__);
}

TEST(MemorySanitizerOrigins, SHIFT) {
  if (!TrackingOrigins()) return;
  EXPECT_POISONED_O(v_u8 = *GetPoisonedO<U8>(0, __LINE__) >> 10, __LINE__);
  EXPECT_POISONED_O(v_s8 = *GetPoisonedO<S8>(0, __LINE__) >> 10, __LINE__);
  EXPECT_POISONED_O(v_s8 = *GetPoisonedO<S8>(0, __LINE__) << 10, __LINE__);
  EXPECT_POISONED_O(v_u8 = 10U << *GetPoisonedO<U8>(0, __LINE__), __LINE__);
  EXPECT_POISONED_O(v_s8 = -10 >> *GetPoisonedO<S8>(0, __LINE__), __LINE__);
  EXPECT_POISONED_O(v_s8 = -10 << *GetPoisonedO<S8>(0, __LINE__), __LINE__);
}

template<class T, int N>
void MemCpyTest() {
  int ox = __LINE__;
  T *x = new T[N];
  T *y = new T[N];
  T *z = new T[N];
  __msan_poison(x, N * sizeof(T));
  __msan_set_origin(x, N * sizeof(T), ox);
  __msan_set_origin(y, N * sizeof(T), 777777);
  __msan_set_origin(z, N * sizeof(T), 888888);
  v_p = x;
  memcpy(y, v_p, N * sizeof(T));
  EXPECT_POISONED_O(v_s1 = y[0], ox);
  EXPECT_POISONED_O(v_s1 = y[N/2], ox);
  EXPECT_POISONED_O(v_s1 = y[N-1], ox);
  v_p = x;
  memmove(z, v_p, N * sizeof(T));
  EXPECT_POISONED_O(v_s1 = z[0], ox);
  EXPECT_POISONED_O(v_s1 = z[N/2], ox);
  EXPECT_POISONED_O(v_s1 = z[N-1], ox);
}

TEST(MemorySanitizerOrigins, LargeMemCpy) {
  if (!TrackingOrigins()) return;
  MemCpyTest<U1, 10000>();
  MemCpyTest<U8, 10000>();
}

TEST(MemorySanitizerOrigins, SmallMemCpy) {
  if (!TrackingOrigins()) return;
  MemCpyTest<U8, 1>();
  MemCpyTest<U8, 2>();
  MemCpyTest<U8, 3>();
}

TEST(MemorySanitizerOrigins, Select) {
  if (!TrackingOrigins()) return;
  v_s8 = g_one ? 1 : *GetPoisonedO<S4>(0, __LINE__);
  EXPECT_POISONED_O(v_s8 = *GetPoisonedO<S4>(0, __LINE__), __LINE__);
  S4 x;
  __msan_break_optimization(&x);
  x = g_1 ? *GetPoisonedO<S4>(0, __LINE__) : 0;

  EXPECT_POISONED_O(v_s8 = g_1 ? *GetPoisonedO<S4>(0, __LINE__) : 1, __LINE__);
  EXPECT_POISONED_O(v_s8 = g_0 ? 1 : *GetPoisonedO<S4>(0, __LINE__), __LINE__);
}

extern "C"
NOINLINE void AllocaTOTest() {
  int ar[100];
  __msan_break_optimization(ar);
  v_s8 = ar[10];
  // fprintf(stderr, "Descr: %s\n",
  //        __msan_get_origin_descr_if_stack(__msan_get_origin_tls()));
}

TEST(MemorySanitizerOrigins, Alloca) {
  if (!TrackingOrigins()) return;
  EXPECT_POISONED_S(AllocaTOTest(), "ar@AllocaTOTest");
  EXPECT_POISONED_S(AllocaTOTest(), "ar@AllocaTOTest");
  EXPECT_POISONED_S(AllocaTOTest(), "ar@AllocaTOTest");
  EXPECT_POISONED_S(AllocaTOTest(), "ar@AllocaTOTest");
}

// FIXME: replace with a lit-like test.
TEST(MemorySanitizerOrigins, AllocaDeath) {
  if (!TrackingOrigins()) return;
  EXPECT_DEATH(AllocaTOTest(), "ORIGIN: stack allocation ar@AllocaTOTest");
}

int main(int argc, char **argv) {
  __msan_set_exit_code(33);
  __msan_set_poison_in_malloc(1);
  testing::InitGoogleTest(&argc, argv);
  int res = RUN_ALL_TESTS();
  return res;
}
