#include "msan.h"
#include "sanitizer_common/sanitizer_common.h"
#include <interception/interception.h>

// ACHTUNG! No system header includes in this file.

typedef uptr size_t;
typedef sptr ssize_t;
using namespace __msan;

#define ENSURE_MSAN_INITED() do { \
    CHECK(!msan_init_is_running);       \
  if (!msan_inited) { \
    __msan_init(); \
  } \
} while (0)

#define CHECK_UNPOISONED(x, n) \
  do { \
  sptr offset = __msan_test_shadow(x, n); \
  if (offset >= 0) { \
  Printf("UMR in %s at offset %d\n", __FUNCTION__, offset); \
  __msan_warning(); \
  } \
  } while (0)

INTERCEPTOR(size_t, fread, void *ptr, size_t size, size_t nmemb, void *file) {
  ENSURE_MSAN_INITED();
  size_t res = REAL(fread)(ptr, size, nmemb, file);
  if (res > 0)
    __msan_unpoison(ptr, res * size);
  return res;
}

INTERCEPTOR(ssize_t, read, int fd, void *ptr, size_t count) {
  ENSURE_MSAN_INITED();
  ssize_t res = REAL(read)(fd, ptr, count);
  if (res > 0)
    __msan_unpoison(ptr, res);
  return res;
}

INTERCEPTOR(void*, memcpy, void* dest, const void* src, size_t n) {
  ENSURE_MSAN_INITED();
  void* res = REAL(memcpy)(dest, src, n);
  __msan_copy_poison(dest, src, n);
  return res;
}

INTERCEPTOR(void*, memmove, void* dest, const void* src, size_t n) {
  ENSURE_MSAN_INITED();
  void* res = REAL(memmove)(dest, src, n);
  __msan_move_poison(dest, src, n);
  return res;
}

INTERCEPTOR(void*, memset, void *s, int c, size_t n) {
  ENSURE_MSAN_INITED();
  void* res = REAL(memset)(s, c, n);
  __msan_unpoison(s, n);
  return res;
}

INTERCEPTOR(int, posix_memalign, void **memptr, size_t alignment, size_t size) {
  CHECK_EQ(alignment & (alignment - 1), 0);
  *memptr = MsanReallocate(0, size, alignment, false);
  CHECK_NE(memptr, 0);
  return 0;
}

INTERCEPTOR(void, free, void *ptr) {
  ENSURE_MSAN_INITED();
  if (ptr == 0) return;
  MsanDeallocate(ptr);
}

INTERCEPTOR(size_t, strlen, const char* s) {
  ENSURE_MSAN_INITED();
  size_t res = REAL(strlen)(s);
  // CHECK_UNPOISONED(s, res + 1);
  return res;
}

INTERCEPTOR(size_t, strnlen, const char* s, size_t n) {
  ENSURE_MSAN_INITED();
  size_t res = REAL(strnlen)(s, n);
  size_t scan_size = (res == n) ? res : res + 1;
  // CHECK_UNPOISONED(s, scan_size);
  return res;
}

INTERCEPTOR(char*, strcpy, char* dest, const char* src) {
  ENSURE_MSAN_INITED();
  size_t n = REAL(strlen)(src);
  char* res = REAL(strcpy)(dest, src);
  __msan_copy_poison(dest, src, n + 1);
  return res;
}

INTERCEPTOR(char*, strncpy, char* dest, const char* src, size_t n) {
  ENSURE_MSAN_INITED();
  size_t copy_size = REAL(strnlen)(src, n);
  if (copy_size < n)
    copy_size++; // trailing \0
  char* res = REAL(strncpy)(dest, src, n);
  __msan_copy_poison(dest, src, copy_size);
  return res;
}

// INTERCEPTOR(char*, gcvt, double number, size_t ndigit, char* buf) {
//   ENSURE_MSAN_INITED();
//   char* res = REAL(gcvt)(number, ndigit, buf);
//   size_t n = REAL(strlen)(buf);
//   __msan_unpoison(buf, n + 1);
//   return res;
// }

INTERCEPTOR(char*, strcat, char* dest, const char* src) {
  ENSURE_MSAN_INITED();
  size_t src_size = REAL(strlen)(src);
  size_t dest_size = REAL(strlen)(dest);
  char* res = REAL(strcat)(dest, src);
  __msan_copy_poison(dest + dest_size, src, src_size + 1);
  return res;
}

INTERCEPTOR(char*, strncat, char* dest, const char* src, size_t n) {
  ENSURE_MSAN_INITED();
  size_t dest_size = REAL(strlen)(dest);
  size_t copy_size = REAL(strlen)(src);
  if (copy_size < n)
    copy_size++; // trailing \0
  char* res = REAL(strncat)(dest, src, n);
  __msan_copy_poison(dest + dest_size, src, copy_size);
  return res;
}

INTERCEPTOR(char*, getenv, char* name) {
  ENSURE_MSAN_INITED();
  char* res = REAL(getenv)(name);
  if (res)
    __msan_unpoison(res, REAL(strlen)(res) + 1);
  return res;
}


INTERCEPTOR(void *, calloc, size_t nmemb, size_t size) {
  if (!msan_inited) {
    // Hack: dlsym calls calloc before REAL(calloc) is retrieved from dlsym.
    const size_t kCallocPoolSize = 1024;
    static uptr calloc_memory_for_dlsym[kCallocPoolSize];
    static size_t allocated;
    size_t size_in_words = ((nmemb * size) + kWordSize - 1) / kWordSize;
    void *mem = (void*)&calloc_memory_for_dlsym[allocated];
    allocated += size_in_words;
    CHECK(allocated < kCallocPoolSize);
    return mem;
  }

  return MsanReallocate(0, nmemb * size, sizeof(u64), true);
}

INTERCEPTOR(void *, realloc, void *ptr, size_t size) {
  return MsanReallocate(ptr, size, sizeof(u64), false);
}

INTERCEPTOR(void *, malloc, size_t size) {
  return MsanReallocate(0, size, sizeof(u64), false);
}

namespace __msan {
void InitializeInterceptors() {
  static int inited = 0;
  CHECK_EQ(inited, 0);
  inited = 1;
  CHECK(INTERCEPT_FUNCTION(posix_memalign));
  CHECK(INTERCEPT_FUNCTION(malloc));
  CHECK(INTERCEPT_FUNCTION(calloc));
  CHECK(INTERCEPT_FUNCTION(realloc));
  CHECK(INTERCEPT_FUNCTION(free));
  CHECK(INTERCEPT_FUNCTION(fread));
  CHECK(INTERCEPT_FUNCTION(read));
  CHECK(INTERCEPT_FUNCTION(memcpy));
  CHECK(INTERCEPT_FUNCTION(memset));
  CHECK(INTERCEPT_FUNCTION(memmove));
  CHECK(INTERCEPT_FUNCTION(strcpy));
  CHECK(INTERCEPT_FUNCTION(strncpy));
  CHECK(INTERCEPT_FUNCTION(strlen));
  CHECK(INTERCEPT_FUNCTION(strnlen));
  // CHECK(INTERCEPT_FUNCTION(gcvt));
  CHECK(INTERCEPT_FUNCTION(strcat));
  CHECK(INTERCEPT_FUNCTION(strncat));
  CHECK(INTERCEPT_FUNCTION(getenv));
}
}  // namespace __msan
