#include "msan.h"
#include "sanitizer_common/sanitizer_common.h"
#include <interception/interception.h>

// ACHTUNG! No system header includes in this file.

typedef uptr size_t;
using namespace __msan;

INTERCEPTOR(size_t, fread, void *ptr, size_t size, size_t nmemb, void *file) {
  size_t res = REAL(fread)(ptr, size, nmemb, file);
  if (res > 0)
    __msan_unpoison(ptr, res * size);
  return res;
}

INTERCEPTOR(void*, memcpy, void* dest, const void* src, size_t n) {
  void* res = REAL(memcpy)(dest, src, n);
  __msan_copy_poison(dest, src, n);
  return res;
}

INTERCEPTOR(void*, memset, void *s, int c, size_t n) {
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
  if (ptr == 0) return;
  MsanDeallocate(ptr);
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
  CHECK(INTERCEPT_FUNCTION(memcpy));
  CHECK(INTERCEPT_FUNCTION(memset));

}
}  // namespace __msan
