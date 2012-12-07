//===-- msan.cc -----------------------------------------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file is a part of MemorySanitizer.
//
// MemorySanitizer runtime.
//===----------------------------------------------------------------------===//

#include "msan_interface.h"
#include "msan.h"
#include "sanitizer_common/sanitizer_atomic.h"
#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_libc.h"
#include "sanitizer_common/sanitizer_mutex.h"
#include "sanitizer_common/sanitizer_flags.h"
#include "sanitizer_common/sanitizer_stackdepot.h"
#include "sanitizer_common/sanitizer_stacktrace.h"
#include "sanitizer_common/sanitizer_symbolizer.h"

#include <interception/interception.h>

// ACHTUNG! No system header includes in this file.

using namespace __sanitizer;

// Globals.
static THREADLOCAL int msan_expect_umr = 0;
static THREADLOCAL int msan_expected_umr_found = 0;

static int msan_running_under_dr = 0;

SANITIZER_INTERFACE_ATTRIBUTE
THREADLOCAL u64 __msan_param_tls[100];

SANITIZER_INTERFACE_ATTRIBUTE
THREADLOCAL u32       __msan_param_origin_tls[100];

SANITIZER_INTERFACE_ATTRIBUTE
THREADLOCAL u64 __msan_retval_tls[8];

SANITIZER_INTERFACE_ATTRIBUTE
THREADLOCAL u32       __msan_retval_origin_tls;

SANITIZER_INTERFACE_ATTRIBUTE
THREADLOCAL u64 __msan_va_arg_tls[100];

SANITIZER_INTERFACE_ATTRIBUTE
THREADLOCAL u64 __msan_va_arg_overflow_size_tls;

SANITIZER_INTERFACE_ATTRIBUTE
THREADLOCAL u32       __msan_origin_tls;

static THREADLOCAL struct {
  uptr stack_top, stack_bottom;
} __msan_stack_bounds;

StaticSpinMutex report_mu;

extern const int __msan_track_origins;
int __msan_get_track_origins() {
  return __msan_track_origins;
}

static bool IsRunningUnderDr() {
  return internal_strstr(__msan::GetProcSelfMaps(), "libdynamorio") != 0;
}

namespace __msan {

Flags flags = {
  false,  // poison_heap_with_zeroes
  false,  // poison_stack_with_zeroes
  true,   // poison_in_malloc
  67,     // exit_code
  20,     // num_callers
  true,   // report_umrs
  false,  // verbosity
};
int msan_inited = 0;
bool msan_init_is_running;

// Array of stack origins.
// FIXME: make it resizable.
static const uptr kNumStackOriginDescrs = 1024 * 1024;
static const char *StackOriginDescr[kNumStackOriginDescrs];
static atomic_uint32_t NumStackOriginDescrs;


void ParseFlagsFromString(Flags *f, const char *str) {
  ParseFlag(str, &f->poison_heap_with_zeroes, "poison_heap_with_zeroes");
  ParseFlag(str, &f->poison_stack_with_zeroes, "poison_stack_with_zeroes");
  ParseFlag(str, &f->poison_in_malloc, "poison_in_malloc");
  ParseFlag(str, &f->exit_code, "exit_code");
  ParseFlag(str, &f->num_callers, "num_callers");
  ParseFlag(str, &f->report_umrs, "report_umrs");
  ParseFlag(str, &f->verbosity, "verbosity");
}

static void GetCurrentStackBounds(uptr *stack_top, uptr *stack_bottom) {
  if (__msan_stack_bounds.stack_top == 0) {
    // Break recursion (GetStackTrace -> GetThreadStackTopAndBottom ->
    // realloc -> GetStackTrace).
    __msan_stack_bounds.stack_top = __msan_stack_bounds.stack_bottom = 1;
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
  StackTrace::PrintStack(stack.trace, stack.size, true, "", 0);
}

void PrintWarning(uptr pc, uptr bp) {
  PrintWarningWithOrigin(pc, bp, __msan_origin_tls);
}

void PrintWarningWithOrigin(uptr pc, uptr bp, u32 origin) {
  if (!__msan::flags.report_umrs) return;
  if (msan_expect_umr) {
    // Printf("Expected UMR\n");
    __msan_origin_tls = origin;
    msan_expected_umr_found = 1;
    return;
  }

  GenericScopedLock<StaticSpinMutex> lock(&report_mu);

  Report(" WARNING: MemorySanitizer: UMR (uninitialized-memory-read)\n");
  PrintCurrentStackTrace(pc, bp);
  if (__msan_track_origins) {
    Printf("  raw origin id: %d\n", origin);
    if (origin == 0 || origin == (u32)-1) {
      Printf("  ORIGIN: invalid (%x). Might be a bug in MemorySanitizer, "
             "please report to MemorySanitizer developers.\n",
             origin);
    } else if (const char *so = __msan_get_origin_descr_if_stack(origin)) {
      Printf("  ORIGIN: stack allocation: %s\n", so);
    } else if (origin != 0) {
      uptr size = 0;
      const uptr *trace = StackDepotGet(origin, &size);
      Printf("  ORIGIN: heap allocation:\n");
      StackTrace::PrintStack(trace, size, true, "", 0);
    }
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
  (void)sp;
  __msan::PrintWarning(pc, bp);
}

void __msan_warning_noreturn() {
  GET_CALLER_PC_BP_SP;
  (void)sp;
  __msan::PrintWarning(pc, bp);
  Die();
}

void __msan_init() {
  using namespace __msan;
  if (msan_inited) return;
  msan_init_is_running = 1;

  report_mu.Init();

  SetDieCallback(MsanDie);
  __msan::InitializeInterceptors();

  ReplaceOperatorsNewAndDelete();
  if (StackSizeIsUnlimited()) {
    // Printf("Unlimited stack, doing reexec\n");
    SetStackSizeLimitInBytes(32 * 1024 * 1024);
    ReExec();
  }
  const char *msan_options = GetEnv("MSAN_OPTIONS");
  ParseFlagsFromString(&flags, msan_options);
  if (flags.verbosity)
    Printf("MSAN_OPTIONS: %s\n", msan_options ? msan_options : "<empty>");
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

  __msan::InstallTrapHandler();

  const char *external_symbolizer = GetEnv("MSAN_SYMBOLIZER_PATH");
  if (external_symbolizer && external_symbolizer[0]) {
    CHECK(InitializeExternalSymbolizer(external_symbolizer));
  }

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
    GET_CALLER_PC_BP_SP;
    (void)sp;
    __msan::PrintCurrentStackTrace(pc, bp);
    Die();
  }
  msan_expect_umr = expect_umr;
}

void __msan_print_shadow(const void *x, uptr size) {
  unsigned char *s = (unsigned char*)MEM_TO_SHADOW(x);
  u32 *o = (u32*)MEM_TO_ORIGIN(x);
  for (uptr i = 0; i < size; i++) {
    Printf("%x%x ", s[i] >> 4, s[i] & 0xf);
  }
  Printf("\n");
  if (__msan_track_origins) {
    for (uptr i = 0; i < size / 4; i++) {
      Printf(" o: %x ", o[i]);
    }
    Printf("\n");
  }
}

void __msan_print_param_shadow() {
  for (int i = 0; i < 16; i++) {
    Printf("#%d:%zx ", i, __msan_param_tls[i]);
  }
  Printf("\n");
}

sptr __msan_test_shadow(const void *x, uptr size) {
  unsigned char *s = (unsigned char*)MEM_TO_SHADOW((uptr)x);
  for (uptr i = 0; i < size; ++i)
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
  u64 p;
  asm("mov %%fs:0, %0"
      : "=r"(p) ::);
  return (void*)p;
}

int __msan_get_retval_tls_offset() {
  // volatile here is needed to avoid UB, because the compiler thinks that we
  // are doing address arithmetics on unrelated pointers, and takes some
  // shortcuts
  volatile sptr retval_tls_p = (sptr)&__msan_retval_tls;
  volatile sptr tls_base_p = (sptr)get_tls_base();
  return retval_tls_p - tls_base_p;
}

int __msan_get_param_tls_offset() {
  // volatile here is needed to avoid UB, because the compiler thinks that we
  // are doing address arithmetics on unrelated pointers, and takes some
  // shortcuts
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
  uptr x = MEM_TO_ORIGIN((uptr)a);
  uptr beg = x & ~3UL;  // align down.
  uptr end = (x + size + 3) & ~3UL;  // align up.
  u64 origin64 = ((u64)origin << 32) | origin;
  // This is like memset, but the value is 32-bit. We unroll by 2 two write
  // 64-bits at once. May want to unroll further to get 128-bit stores.
  if (beg & 7ULL) {
    *(u32*)beg = origin;
    beg += 4;
  }
  for (uptr addr = beg; addr < (end & ~7UL); addr += 8)
    *(u64*)addr = origin64;
  if (end & 7ULL)
    *(u32*)(end - 4) = origin;
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
