#include "msan_interface.h"
#include "msan.h"
#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_libc.h"
#include "sanitizer_common/sanitizer_flags.h"

#include <interception/interception.h>

// ACHTUNG! No system header includes in this file.

using namespace __sanitizer;

// Globals.
static THREADLOCAL int msan_expect_umr = 0;
static THREADLOCAL int msan_expected_umr_found = 0;

static int msan_running_under_dr = 0;
THREADLOCAL long long __msan_param_tls[100];
THREADLOCAL long long __msan_retval_tls[8];
THREADLOCAL long long __msan_va_arg_tls[100];
THREADLOCAL long long __msan_va_arg_overflow_size_tls;

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
  __msan::BacktraceStackTrace();
  if (__msan::flags.exit_code >= 0) {
    Printf("Exiting\n");
    Die();
  }
}

namespace __msan {

Flags flags = {
  false,  // poison_with_zeroes
  true,   // poison_in_malloc
  67,     // exit_code
};
int msan_inited = 0;
bool msan_init_is_running;


void ParseFlagsFromString(Flags *f, const char *str) {
  ParseFlag(str, &f->poison_with_zeroes, "poison_with_zeroes");
  ParseFlag(str, &f->poison_in_malloc, "poison_in_malloc");
  ParseFlag(str, &f->exit_code, "exit_code");
}

}  // namespace __msan


extern "C"
void __msan_init() {
  using namespace __msan;
  if (msan_inited) return;
  ParseFlagsFromString(&flags, GetEnv("MSAN_OPTIONS"));
  msan_init_is_running = 1;
  msan_running_under_dr = IsRunningUnderDr();
  __msan_clear_on_return();
  if (!InitShadow(/*true*/ false, true, true)) {
    // FIXME: eugenis, do we need *false* above?
    Printf("FATAL: MemorySanitizer can not mmap the shadow memory\n");
    Printf("FATAL: Make sure to compile with -fPIE and to link with -pie.\n");
    CatProcSelfMaps();
    Die();
  }

  __msan::InitializeInterceptors();
  __msan::InstallTrapHandler();
  // Printf("MemorySanitizer init done\n");
  msan_init_is_running = 0;
  msan_inited = 1;
}

// Interface.

void __msan_set_exit_code(int exit_code) {
  __msan::flags.exit_code = exit_code;
}
void __msan_set_expect_umr(int expect_umr) {
  if (expect_umr) {
    msan_expected_umr_found = 0;
  } else if (!msan_expected_umr_found) {
    Printf("Expected UMR not found\n");
    __msan::BacktraceStackTrace();
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
  for (int i = 0; i < 16; i++) {
    Printf("#%d:%zx ", i, __msan_param_tls[i]);
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
  int old = __msan::flags.poison_in_malloc;
  __msan::flags.poison_in_malloc = do_poison;
  return old;
}

void __msan_break_optimization(void *x) { }

int  __msan_has_dynamic_component() {
  return msan_running_under_dr;
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

void __msan_partial_poison(void* data, void* shadow, uptr size) {
  internal_memcpy((void*)MEM_TO_SHADOW((uptr)data), shadow, size);
}

void __msan_load_unpoisoned(void *src, uptr size, void *dst) {
  internal_memcpy(dst, src, size);
  __msan_unpoison(dst, size);
}

#include "msan_linux_inl.h"
