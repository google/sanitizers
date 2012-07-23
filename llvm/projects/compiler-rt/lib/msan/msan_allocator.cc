#include "sanitizer_common/sanitizer_allocator64.h"
#include "msan.h"
#include <interception/interception.h>

DECLARE_REAL(int, posix_memalign, void **memptr, uptr alignment, uptr size);
DECLARE_REAL(void, free, void *ptr);

namespace __msan {
static const int kMsanMallocMagic = 0xCA4D;

void *MsanReallocate(void *oldp, uptr size, uptr alignment, bool zeroise) {
  __msan_init();
  CHECK(msan_inited);
  uptr extra_bytes = 2 * sizeof(u64*);
  if (alignment > extra_bytes)
    extra_bytes = alignment;
  uptr old_size = 0;
  void *real_oldp = 0;
  if (oldp) {
    char *beg = (char*)(oldp);
    u64 *p = (u64 *)beg;
    old_size = p[-2] >> 16;
    CHECK((p[-2] & 0xffffULL) == kMsanMallocMagic);
    char *end = beg + size;
    real_oldp = (void*)p[-1];
  }
  void *mem = 0;
  int res = REAL(posix_memalign)(&mem, alignment, size + extra_bytes);
  if (res == 0) {
    char *beg = (char*)mem + extra_bytes;
    char *end = beg + size;
    u64 *p = (u64 *)beg;
    p[-2] = (size << 16) | kMsanMallocMagic;
    p[-1] = (u64)mem;
    // Printf("MSAN POISONS on malloc [%p, %p) rbeg: %p\n", beg, end, mem);
    if (zeroise) {
      internal_memset(beg, 0, size);
    } else {
      if (__msan::flags.poison_in_malloc)
        __msan_poison(beg, end - beg);
    }
    mem = beg;
  }

  if (old_size) {
    uptr min_size = size < old_size ? size : old_size;
    if (mem) {
      internal_memcpy(mem, oldp, min_size);
      __msan_copy_poison(mem, oldp, min_size);
    }
    __msan_unpoison(oldp, old_size);
    REAL(free(real_oldp));
  }
  return mem;
}

void MsanDeallocate(void *ptr) {
  __msan_init();
  char *beg = (char*)(ptr);
  u64 *p = (u64 *)beg;
  uptr size = p[-2] >> 16;
  CHECK((p[-2] & 0xffffULL) == kMsanMallocMagic);
  char *end = beg + size;
  // Printf("MSAN UNPOISONS on free [%p, %p)\n", beg, end);
  __msan_unpoison(beg, end - beg);
  REAL(free((void*)p[-1]));
}

}  // namespace __msan
