#include "msan_interface.h"
#include "msan.h"
#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_libc.h"

#include <interception/interception.h>

// ACHTUNG! No system header includes in this file.

#define THREAD_LOCAL __thread

using namespace __sanitizer;

DECLARE_REAL(int, posix_memalign, void **memptr, uptr alignment, uptr size);
DECLARE_REAL(void, free, void *ptr);


// Globals.
static int msan_exit_code = 67;
static int msan_poison_in_malloc = 1;
static THREAD_LOCAL int msan_expect_umr = 0;
static THREAD_LOCAL int msan_expected_umr_found = 0;

static int msan_running_under_pin = 0;
static int msan_running_under_dr = 0;
THREAD_LOCAL long long __msan_param_tls[100];
THREAD_LOCAL long long __msan_retval_tls[8];
static long long *main_thread_param_tls;

static const int kMsanMallocMagic = 0xCA4D;


static bool IsRunningUnderPin() {
  return internal_strstr(__msan::GetProcSelfMaps(), "/pinbin") != 0;
}

static bool IsRunningUnderDr() {
  return internal_strstr(__msan::GetProcSelfMaps(), "libdynamorio") != 0;
}

void __msan_warning() {
  if (msan_expect_umr) {
    // Printf("Expected UMR\n");
    msan_expected_umr_found = 1;
    return;
  }
  Printf("***UMR***\n");
  msan_running_under_dr ?
    __msan::BacktraceStackTrace() : __msan::GdbBackTrace();
  if (msan_exit_code >= 0) {
    Printf("Exiting\n");
    Die();
  }
}

namespace __msan {
int msan_inited = 0;
bool msan_init_is_running;

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
      if (msan_poison_in_malloc)
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


extern "C"
void __msan_init() {
  using namespace __msan;
  if (msan_inited) return;
  msan_init_is_running = 1;
  main_thread_param_tls = __msan_param_tls;
  msan_running_under_pin = IsRunningUnderPin();
  msan_running_under_dr = IsRunningUnderDr();
  // Must call it here for PIN to intercept it.
  __msan_clear_on_return();
  if (!msan_running_under_pin) {
    if (!InitShadow(/*true*/ false, true, true)) {
      Printf("FATAL: MemorySanitizer can not mmap the shadow memory\n");
      Printf("FATAL: Make sure to compile with -fPIE and to link with -pie.\n");
      CatProcSelfMaps();
      Die();
    }
  }

  __msan::InitializeInterceptors();
  __msan::InstallTrapHandler();
  // Printf("MemorySanitizer init done\n");
  msan_init_is_running = 0;
  msan_inited = 1;
}

// Interface.

void __msan_unpoison(void *a, uptr size) {
  if ((uptr)a < 0x7f0000000000) return;
  internal_memset((void*)MEM_TO_SHADOW((uptr)a), 0, size);
}
void __msan_poison(void *a, uptr size) {
  if ((uptr)a < 0x7f0000000000) return;
  internal_memset((void*)MEM_TO_SHADOW((uptr)a), -1, size);
}

void __msan_copy_poison(void *dst, const void *src, uptr size) {
  if ((uptr)dst < 0x7f0000000000) return;
  if ((uptr)src < 0x7f0000000000) return;
  internal_memcpy((void*)MEM_TO_SHADOW((uptr)dst),
         (void*)MEM_TO_SHADOW((uptr)src), size);
}

void __msan_move_poison(void *dst, const void *src, uptr size) {
  if ((uptr)dst < 0x7f0000000000) return;
  if ((uptr)src < 0x7f0000000000) return;
  internal_memmove((void*)MEM_TO_SHADOW((uptr)dst),
         (void*)MEM_TO_SHADOW((uptr)src), size);
}

void __msan_set_exit_code(int exit_code) {
  msan_exit_code = exit_code;
}
void __msan_set_expect_umr(int expect_umr) {
  if (expect_umr) {
    msan_expected_umr_found = 0;
  } else if (!msan_expected_umr_found) {
    Printf("Expected UMR not found\n");
    msan_running_under_dr ?
      __msan::BacktraceStackTrace() : __msan::GdbBackTrace();
    Die();
  }
  msan_expect_umr = expect_umr;
}

void __msan_print_shadow(const void *x, uptr size) {
  unsigned char *s = (unsigned char*)MEM_TO_SHADOW((uptr)x);
  for (uptr i = 0; i < (uptr)size; i++) {
    Printf("%x ", s[i]);
  }
  Printf("\n");
}

void __msan_print_param_shadow() {
  for (int i = 0; i < 4; i++) {
    Printf("%llx ", __msan_param_tls[i]);
  }
  Printf("\n");
}

sptr __msan_test_shadow(const void *x, uptr size) {
  const char* s = (char*)x;
  for (sptr i = 0; i < size; ++i)
    if (s[i])
      return i;
  return -1;
}

int __msan_set_poison_in_malloc(int do_poison) {
  int old = msan_poison_in_malloc;
  msan_poison_in_malloc = do_poison;
  return old;
}

void __msan_break_optimization(void *x) { }

int  __msan_has_dynamic_component() {
  return msan_running_under_pin || msan_running_under_dr;
}

NOINLINE
void __msan_clear_on_return() {
  __msan_param_tls[0] = 0;
}

static void* get_tls_base() {
  unsigned long long p;
  asm("mov %%fs:0, %0"
      : "=r"(p) ::);
  return (void*)p;
}

int __msan_get_retval_tls_offset() {
  // volatile here is needed to avoid UB, because the compiler thinks that we are doing address
  // arithmetics on unrelated pointers, and takes some shortcuts
  volatile sptr retval_tls_p = (sptr)&__msan_retval_tls;
  volatile sptr tls_base_p = (sptr)get_tls_base();
  return retval_tls_p - tls_base_p;
}

#include "msan_linux_inl.h"
