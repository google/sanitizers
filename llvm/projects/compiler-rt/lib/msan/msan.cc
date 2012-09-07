#include "msan_interface.h"
#include "msan.h"
#include "sanitizer_common/sanitizer_atomic.h"
#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_libc.h"
#include "sanitizer_common/sanitizer_flags.h"
#include "sanitizer_common/sanitizer_stacktrace.h"

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
THREADLOCAL u32       __msan_origin_tls;

THREADLOCAL struct { uptr stack_top, stack_bottom; } __msan_stack_bounds;

static bool IsRunningUnderDr() {
  return internal_strstr(__msan::GetProcSelfMaps(), "libdynamorio") != 0;
}

namespace __msan {

Flags flags = {
  false,  // poison_with_zeroes
  true,   // poison_in_malloc
  67,     // exit_code
  true,   // fast_unwinder
  20,     // num_callers
};
int msan_inited = 0;
bool msan_init_is_running;

// Array of stack origins.
// FIXME: make it resizable.
static const uptr kNumStackOriginDescrs = 1024 * 1024;
static const char *StackOriginDescr[kNumStackOriginDescrs];
static atomic_uint32_t NumStackOriginDescrs;


void ParseFlagsFromString(Flags *f, const char *str) {
  ParseFlag(str, &f->poison_with_zeroes, "poison_with_zeroes");
  ParseFlag(str, &f->poison_in_malloc, "poison_in_malloc");
  ParseFlag(str, &f->exit_code, "exit_code");
  ParseFlag(str, &f->fast_unwinder, "fast_unwinder");
  ParseFlag(str, &f->num_callers, "num_callers");
}

static void GetCurrentStackBounds(uptr *stack_top, uptr *stack_bottom) {
  if (__msan_stack_bounds.stack_top == 0) {
    GetThreadStackTopAndBottom(false,
                               &__msan_stack_bounds.stack_top,
                               &__msan_stack_bounds.stack_bottom);
  }
  *stack_top = __msan_stack_bounds.stack_top;
  *stack_bottom = __msan_stack_bounds.stack_bottom;
}

void GetStackTrace(StackTrace *stack, uptr max_s, uptr pc, uptr bp) {
  uptr stack_top, stack_bottom;
  GetCurrentStackBounds(&stack_top, &stack_bottom);
  stack->size = 0;
  stack->trace[0] = pc;
  stack->max_size = max_s;
  stack->FastUnwindStack(pc, bp, stack_top, stack_bottom);
}

static void PrintCurrentStackTrace(uptr pc, uptr bp) {
  StackTrace stack;
  GetStackTrace(&stack, kStackTraceMax, pc, bp);
  stack.PrintStack(stack.trace, stack.size, false, "", 0);
}

void PrintWarning(uptr pc, uptr bp) {
  if (msan_expect_umr) {
    // Printf("Expected UMR\n");
    msan_expected_umr_found = 1;
    return;
  }
  Report(" WARNING: MemorySanitizer: UMR (uninitialized-memory-read)\n");
  if (flags.fast_unwinder)
    PrintCurrentStackTrace(pc, bp);
  else
    BacktraceStackTrace();
  if (__msan_track_origins) {
    Report("  ORIGIN: %x\n", __msan_origin_tls);
  }
  if (__msan::flags.exit_code >= 0) {
    Printf("Exiting\n");
    Die();
  }
}

}  // namespace __msan

// Interface.

void __msan_warning() {
  GET_CALLER_PC_BP_SP;
  __msan::PrintWarning(pc, bp);
}

void __msan_init() {
  using namespace __msan;
  if (msan_inited) return;
  ReplaceOperatorsNewAndDelete();
  if (StackIsUnlimited()) {
    // Printf("Unlimited stack, doing reexec\n");
    SetSaneStackLimit();
    ReExec();
  }
  ParseFlagsFromString(&flags, GetEnv("MSAN_OPTIONS"));
  msan_init_is_running = 1;
  msan_running_under_dr = IsRunningUnderDr();
  __msan_clear_on_return();
  if (__msan_track_origins)
    Printf("msan_track_origins\n");
  if (!InitShadow(/*true*/ false, true, true, __msan_track_origins)) {
    // FIXME: eugenis, do we need *false* above?
    Printf("FATAL: MemorySanitizer can not mmap the shadow memory\n");
    Printf("FATAL: Make sure to compile with -fPIE and to link with -pie.\n");
    CatProcSelfMaps();
    Die();
  }

  __msan::InitializeInterceptors();
  __msan::InstallTrapHandler();

  GetThreadStackTopAndBottom(true,
                             &__msan_stack_bounds.stack_top,
                             &__msan_stack_bounds.stack_bottom);
  // Printf("MemorySanitizer init done\n");
  msan_init_is_running = 0;
  msan_inited = 1;
}

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
  unsigned char *s = (unsigned char*)MEM_TO_SHADOW((uptr)x);
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

int __msan_get_param_tls_offset() {
  // volatile here is needed to avoid UB, because the compiler thinks that we are doing address
  // arithmetics on unrelated pointers, and takes some shortcuts
  volatile sptr param_tls_p = (sptr)&__msan_param_tls;
  volatile sptr tls_base_p = (sptr)get_tls_base();
  return param_tls_p - tls_base_p;
}

void __msan_partial_poison(void* data, void* shadow, uptr size) {
  internal_memcpy((void*)MEM_TO_SHADOW((uptr)data), shadow, size);
}

void __msan_load_unpoisoned(void *src, uptr size, void *dst) {
  internal_memcpy(dst, src, size);
  __msan_unpoison(dst, size);
}

void __msan_set_origin(void *a, uptr size, u32 origin) {
  if (!__msan_track_origins) return;
  uptr x = (uptr)a;
  uptr aligned = MEM_TO_ORIGIN(x & ~3ULL);
  for (uptr addr = aligned; addr < aligned + size; addr += 4) {
    *(u32*)addr = origin;
  }
}

// 'descr' is created at compile time and contains '----' in the beginning.
// When we see descr for the first time we replace '----' with a uniq id
// and set the origin to (id | (31-th bit)).
void __msan_set_alloca_origin(void *a, uptr size, const char *descr) {
  static const u32 dash = '-';
  static const u32 first_timer =
      dash + (dash << 8) + (dash << 16) + (dash << 24);
  u32 *id_ptr = (u32*)descr;
  bool print = false;  // internal_strstr(descr + 4, "AllocaTOTest") != 0;
  u32 id = *id_ptr;
  if (id == first_timer) {
    id = atomic_fetch_add(&__msan::NumStackOriginDescrs,
                              1, memory_order_relaxed);
    *id_ptr = id;
    CHECK_LT(id, __msan::kNumStackOriginDescrs);
    __msan::StackOriginDescr[id] = descr + 4;
    if (print)
      Printf("First time: id=%d %s \n", id, descr + 4);
  }
  id |= 1U << 31;
  if (print)
    Printf("__msan_set_alloca_origin: descr=%s id=%x\n", descr + 4, id);
  __msan_set_origin(a, size, id);
}

const char *__msan_get_origin_descr_if_stack(u32 id) {
  if ((id >> 31) == 0) return 0;
  id &= (1U << 31) - 1;
  CHECK_LT(id, __msan::kNumStackOriginDescrs);
  return __msan::StackOriginDescr[id];
}


u32 __msan_get_origin(void *a) {
  if (!__msan_track_origins) return 0;
  uptr x = (uptr)a;
  uptr aligned = x & ~3ULL;
  uptr origin_ptr = MEM_TO_ORIGIN(aligned);
  return *(u32*)origin_ptr;
}

u32 __msan_get_origin_tls() {
  return __msan_origin_tls;
}

#include "msan_linux_inl.h"
