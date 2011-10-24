//===-- asan_rtl.cc ------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file is a part of AddressSanitizer, an address sanity checker.
//
// Main file of the ASan run-time library.
//===----------------------------------------------------------------------===//
#include "asan_allocator.h"
#include "asan_int.h"
#include "asan_interceptors.h"
#include "asan_lock.h"
#include "asan_mapping.h"
#include "asan_stack.h"
#include "asan_stats.h"
#include "asan_thread.h"

#include <algorithm>
#include <map>
#include <dlfcn.h>
#include <execinfo.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/ucontext.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>
// must not include <setjmp.h> on Linux

#ifdef __APPLE__
#include <CoreFoundation/CFBase.h>
#include <setjmp.h>
#include <malloc/malloc.h>
#endif


#ifndef ASAN_NEEDS_SEGV
# define ASAN_NEEDS_SEGV 1
#endif

// -------------------------- Flags ------------------------- {{{1
static const size_t kMallocContextSize = 30;
static int    __asan_flag_atexit;
bool   __asan_flag_fast_unwind = true;

size_t __asan_flag_redzone;  // power of two, >= 32
bool   __asan_flag_mt;  // set to 0 if you have only one thread.
size_t __asan_flag_quarantine_size;
int    __asan_flag_demangle;
bool   __asan_flag_symbolize;
int    __asan_flag_v;
int    __asan_flag_debug;
bool   __asan_flag_poison_shadow;
int    __asan_flag_report_globals;
size_t __asan_flag_malloc_context_size = kMallocContextSize;
int    __asan_flag_stats;
uintptr_t __asan_flag_large_malloc;
bool   __asan_flag_lazy_shadow;
bool   __asan_flag_handle_segv;

// -------------------------- Printf ---------------- {{{1
static FILE *asan_out = NULL;

void __asan_printf(const char *format, ...) {
  const int kLen = 1024 * 4;
  char buffer[kLen];
  va_list args;
  va_start(args, format);
  vsnprintf(buffer, kLen, format, args);
  fwrite(buffer, 1, __asan::real_strlen(buffer), asan_out);
  fflush(asan_out);
  va_end(args);
}


// -------------------------- Globals --------------------- {{{1
int __asan_inited;
bool __asan_init_is_running;

// -------------------------- Interceptors ---------------- {{{1
typedef int (*sigaction_f)(int signum, const struct sigaction *act,
                           struct sigaction *oldact);
typedef sig_t (*signal_f)(int signum, sig_t handler);
typedef void (*longjmp_f)(void *env, int val);
typedef longjmp_f _longjmp_f;
typedef longjmp_f siglongjmp_f;
typedef void (*__cxa_throw_f)(void *, void *, void *);
typedef int (*pthread_create_f)(pthread_t *thread, const pthread_attr_t *attr,
                              void *(*start_routine) (void *), void *arg);

namespace __asan {
sigaction_f             real_sigaction;
signal_f                real_signal;
longjmp_f               real_longjmp;
_longjmp_f              real__longjmp;
siglongjmp_f            real_siglongjmp;
__cxa_throw_f           real___cxa_throw;
pthread_create_f        real_pthread_create;
}  // namespace

// -------------------------- AsanStats ---------------- {{{1
static void PrintMallocStatsArray(const char *name, size_t array[__WORDSIZE]) {
//  Printf("%s", name);
//  for (size_t i = 0; i < __WORDSIZE; i++) {
//    if (!array[i]) continue;
//    Printf("%ld:%06ld; ", i, array[i]);
//  }
//  Printf("\n");
  Printf("%s", name);
  for (size_t i = 0; i < __WORDSIZE; i++) {
    if (!array[i]) continue;
    Printf("%ld:%03ld; ", i, (array[i] << i) >> 20);
  }
  Printf("\n");
}

void AsanStats::PrintStats() {
  if (!__asan_flag_stats) return;
  Printf("Stats: %ldM malloced (%ldM for red zones) by %ld calls\n",
         malloced>>20, malloced_redzones>>20, mallocs);
  Printf("Stats: %ldM realloced by %ld calls\n", realloced>>20, reallocs);
  Printf("Stats: %ldM freed by %ld calls\n", freed>>20, frees);
  Printf("Stats: %ldM really freed by %ld calls\n",
         really_freed>>20, real_frees);
  Printf("Stats: %ldM (%ld pages) mmaped in %ld calls\n",
         mmaped>>20, mmaped / kPageSize, mmaps);

  PrintMallocStatsArray(" mmaps   by size: ", mmaped_by_size);
  PrintMallocStatsArray(" mallocs by size: ", malloced_by_size);
  PrintMallocStatsArray(" frees   by size: ", freed_by_size);
  PrintMallocStatsArray(" rfrees  by size: ", really_freed_by_size);
  Printf("Stats: malloc large: %ld small slow: %ld\n",
         malloc_large, malloc_small_slow);
}

AsanStats __asan_stats;

// -------------------------- Misc ---------------- {{{1
void __asan_show_stats_and_abort() {
  __asan_stats.PrintStats();
  abort();
}

static void PrintBytes(const char *before, uintptr_t *a) {
  uint8_t *bytes = (uint8_t*)a;
#if __WORDSIZE == 64
  Printf("%s"PP": %02x %02x %02x %02x %02x %02x %02x %02x\n",
         before, (uintptr_t)a,
         bytes[0], bytes[1], bytes[2], bytes[3],
         bytes[4], bytes[5], bytes[6], bytes[7]);
#else
  Printf("%s"PP": %02x %02x %02x %02x\n",
         before, (uintptr_t)a,
         bytes[0], bytes[1], bytes[2], bytes[3]);
#endif
}

// ---------------------- Thread ------------------------- {{{1
static void *asan_thread_start(void *arg) {
  AsanThread *t= (AsanThread*)arg;
  AsanThread::SetCurrent(t);
  return t->ThreadStart();
}

// ---------------------- mmap -------------------- {{{1
static void OutOfMemoryMessage(const char *mem_type, size_t size) {
  Printf("==%d== ERROR: AddressSanitizer failed to allocate "
         "0x%lx (%ld) bytes of %s\n",
         getpid(), size, size, mem_type);
}

void *__asan_mmap(void *addr, size_t length, int prot, int flags,
                                    int fd, uint64_t offset) {
#ifndef __APPLE__
// Generally we don't want our mmap() to be wrapped by anyone.
// On Linux we use syscall(), on Mac we don't care for now.
# if __WORDSIZE == 64
  return (void *)syscall(SYS_mmap, addr, length, prot, flags, fd, offset);
# else
  return (void *)syscall(SYS_mmap2, addr, length, prot, flags, fd, offset);
# endif
#else
  return mmap(addr, length, prot, flags, fd, offset);
#endif
}


static char *mmap_pages(size_t start_page, size_t n_pages, const char *mem_type,
                        bool abort_on_failure = true) {
  void *res = __asan_mmap((void*)start_page, kPageSize * n_pages,
                   PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANON | MAP_FIXED | MAP_NORESERVE, 0, 0);
  // Printf("%p => %p\n", (void*)start_page, res);
  char *ch = (char*)res;
  if (res == (void*)-1L && abort_on_failure) {
    OutOfMemoryMessage(mem_type, n_pages * kPageSize);
    __asan_show_stats_and_abort();
  }
  CHECK(res == (void*)start_page || res == (void*)-1L);
  return ch;
}

// mmap range [beg, end]
static char *mmap_range(uintptr_t beg, uintptr_t end, const char *mem_type) {
  CHECK((beg % kPageSize) == 0);
  CHECK(((end + 1) % kPageSize) == 0);
  // Printf("mmap_range "PP" "PP" %ld\n", beg, end, (end - beg) / kPageSize);
  return mmap_pages(beg, (end - beg + 1) / kPageSize, mem_type);
}

// protect range [beg, end]
static void protect_range(uintptr_t beg, uintptr_t end) {
  CHECK((beg % kPageSize) == 0);
  CHECK(((end+1) % kPageSize) == 0);
  // Printf("protect_range "PP" "PP" %ld\n", beg, end, (end - beg) / kPageSize);
  void *res = __asan_mmap((void*)beg, end - beg + 1,
                   PROT_NONE,
                   MAP_PRIVATE | MAP_ANON | MAP_FIXED | MAP_NORESERVE, 0, 0);
  CHECK(res == (void*)beg);
}

// ---------------------- DescribeAddress -------------------- {{{1
static bool DescribeStackAddress(uintptr_t addr, uintptr_t access_size) {
  AsanThread *t = AsanThread::FindThreadByStackAddress(addr);
  if (!t) return false;
  const intptr_t kBufSize = 4095;
  char buf[kBufSize];
  uintptr_t offset = 0;
  const char *frame_descr = t->GetFrameNameByAddr(addr, &offset);
  // This string is created by the compiler and has the following form:
  // "FunctioName n alloc_1 alloc_2 ... alloc_n"
  // where alloc_i looks like "offset size len ObjectName ".
  CHECK(frame_descr);
  // Report the function name and the offset.
  const char *name_end = strchr(frame_descr, ' ');
  CHECK(name_end);
  buf[0] = 0;
  strncat(buf, frame_descr,
          std::min(kBufSize, static_cast<intptr_t>(name_end - frame_descr)));
  Printf("Address "PP" is located at offset %ld "
         "in frame <%s> of T%d's stack:\n",
         addr, offset, buf, t->tid());
  // Report the number of stack objects.
  char *p;
  size_t n_objects = strtol(name_end, &p, 10);
  CHECK(n_objects > 0);
  Printf("  This frame has %ld object(s):\n", n_objects);
  // Report all objects in this frame.
  for (size_t i = 0; i < n_objects; i++) {
    size_t beg, size, len;
    beg  = strtol(p, &p, 10);
    CHECK(beg > 0);
    size = strtol(p, &p, 10);
    CHECK(size > 0);
    len  = strtol(p, &p, 10);
    CHECK(*p == ' ');
    p++;
    buf[0] = 0;
    strncat(buf, p, std::min((size_t)kBufSize, len));
    p += len;
    Printf("    [%ld, %ld) '%s'\n", beg, beg + size, buf);
  }
  Printf("HINT: this may be a false positive if your program uses "
         "some custom stack unwind mechanism\n"
         "      (longjmp and C++ exceptions *are* supported)\n");
  t->summary()->Announce();
  return true;
}

__attribute__((noinline))
static void DescribeAddress(uintptr_t addr, uintptr_t access_size) {
  // Check if this is a global.
  if (__asan_describe_addr_if_global(addr))
    return;

  if (DescribeStackAddress(addr, access_size))
    return;

  // finally, check if this is a heap.
  __asan_describe_heap_address(addr, access_size);
}

// -------------------------- Interceptors ------------------- {{{1
#define OPERATOR_NEW_BODY \
  GET_STACK_TRACE_HERE_FOR_MALLOC;\
  return __asan_memalign(0, size, &stack);

void *operator new(size_t size) { OPERATOR_NEW_BODY; }
void *operator new[](size_t size) { OPERATOR_NEW_BODY; }
void *operator new(size_t size, std::nothrow_t const&) { OPERATOR_NEW_BODY; }
void *operator new[](size_t size, std::nothrow_t const&) { OPERATOR_NEW_BODY; }

#define OPERATOR_DELETE_BODY \
  if (!ptr) return;\
  GET_STACK_TRACE_HERE_FOR_FREE(ptr);\
  __asan_free(ptr, &stack);

void operator delete(void *ptr) { OPERATOR_DELETE_BODY; }
void operator delete[](void *ptr) { OPERATOR_DELETE_BODY; }
void operator delete(void *ptr, std::nothrow_t const&) { OPERATOR_DELETE_BODY; }
void operator delete[](void *ptr, std::nothrow_t const&) {OPERATOR_DELETE_BODY;}

extern "C"
#ifndef __APPLE__
__attribute__((visibility("default")))
#endif
int WRAP(pthread_create)(pthread_t *thread, const pthread_attr_t *attr,
                         void *(*start_routine) (void *), void *arg) {
  GET_STACK_TRACE_HERE(kStackTraceMax, /*fast_unwind*/false);
  AsanThread *t = (AsanThread*)__asan_malloc(sizeof(AsanThread), &stack);
  new(t) AsanThread(AsanThread::GetCurrent()->tid(),
                    start_routine, arg, &stack);
  return __asan::real_pthread_create(thread, attr, asan_thread_start, t);
}

static bool MySignal(int signum) {
  if (signum == SIGILL) return true;
  if (__asan_flag_handle_segv && signum == SIGSEGV) return true;
#ifdef __APPLE__
  if (__asan_flag_handle_segv && signum == SIGBUS) return true;
#endif
  return false;
}

extern "C"
sig_t WRAP(signal)(int signum, sig_t handler) {
  if (!MySignal(signum)) {
    return __asan::real_signal(signum, handler);
  }
  return NULL;
}

extern "C"
int WRAP(sigaction)(int signum, const struct sigaction *act,
                    struct sigaction *oldact) {
  if (!MySignal(signum)) {
    return __asan::real_sigaction(signum, act, oldact);
  }
  return 0;
}


static void UnpoisonStackFromHereToTop() {
  int local_stack;
  uintptr_t top = AsanThread::GetCurrent()->stack_top();
  uintptr_t bottom = ((uintptr_t)&local_stack - kPageSize) & ~(kPageSize-1);
  uintptr_t top_shadow = MemToShadow(top);
  uintptr_t bot_shadow = MemToShadow(bottom);
  __asan::real_memset((void*)bot_shadow, 0, top_shadow - bot_shadow);
}

extern "C" void WRAP(longjmp)(void *env, int val) {
  UnpoisonStackFromHereToTop();
  __asan::real_longjmp(env, val);
}

extern "C" void WRAP(_longjmp)(void *env, int val) {
  UnpoisonStackFromHereToTop();
  __asan::real__longjmp(env, val);
}

extern "C" void WRAP(siglongjmp)(void *env, int val) {
  UnpoisonStackFromHereToTop();
  __asan::real_siglongjmp(env, val);
}

extern "C" void __cxa_throw(void *a, void *b, void *c);

#if ASAN_HAS_EXCEPTIONS
extern "C" void WRAP(__cxa_throw)(void *a, void *b, void *c) {
  UnpoisonStackFromHereToTop();
  __asan::real___cxa_throw(a, b, c);
}
#endif

extern "C" {
// intercept mlock and friends.
// Since asan maps 16T of RAM, mlock is completely unfriendly to asan.
// All functions return 0 (success).
static void MlockIsUnsupported() {
  static bool printed = 0;
  if (printed) return;
  printed = true;
  Printf("INFO: AddressSanitizer ignores mlock/mlockall/munlock/munlockall\n");
}
int mlock(const void *addr, size_t len) {
  MlockIsUnsupported();
  return 0;
}
int munlock(const void *addr, size_t len) {
  MlockIsUnsupported();
  return 0;
}
int mlockall(int flags) {
  MlockIsUnsupported();
  return 0;
}
int munlockall(void) {
  MlockIsUnsupported();
  return 0;
}
}  // extern "C"

// -------------------------- Run-time entry ------------------- {{{1
void GetPcSpBpAx(void *context,
                 uintptr_t *pc, uintptr_t *sp, uintptr_t *bp, uintptr_t *ax) {
  ucontext_t *ucontext = (ucontext_t*)context;
#ifdef __APPLE__
# if __WORDSIZE == 64
  *pc = ucontext->uc_mcontext->__ss.__rip;
  *bp = ucontext->uc_mcontext->__ss.__rbp;
  *sp = ucontext->uc_mcontext->__ss.__rsp;
  *ax = ucontext->uc_mcontext->__ss.__rax;
# else
  *pc = ucontext->uc_mcontext->__ss.__eip;
  *bp = ucontext->uc_mcontext->__ss.__ebp;
  *sp = ucontext->uc_mcontext->__ss.__esp;
  *ax = ucontext->uc_mcontext->__ss.__eax;
# endif  // __WORDSIZE
#else  // assume linux
# if __WORDSIZE == 64
  *pc = ucontext->uc_mcontext.gregs[REG_RIP];
  *bp = ucontext->uc_mcontext.gregs[REG_RBP];
  *sp = ucontext->uc_mcontext.gregs[REG_RSP];
  *ax = ucontext->uc_mcontext.gregs[REG_RAX];
# else
  *pc = ucontext->uc_mcontext.gregs[REG_EIP];
  *bp = ucontext->uc_mcontext.gregs[REG_EBP];
  *sp = ucontext->uc_mcontext.gregs[REG_ESP];
  *ax = ucontext->uc_mcontext.gregs[REG_EAX];
# endif  // __WORDSIZE
#endif
}

static void     ASAN_OnSIGSEGV(int, siginfo_t *siginfo, void *context) {
  uintptr_t addr = (uintptr_t)siginfo->si_addr;
  if (AddrIsInShadow(addr) && __asan_flag_lazy_shadow) {
    // We traped on access to a shadow address. Just map a large chunk around
    // this address.
    const uintptr_t chunk_size = kPageSize << 10;  // 4M
    uintptr_t chunk = addr & ~(chunk_size - 1);
    __asan_mmap((void*)chunk, chunk_size,
                   PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANON | MAP_FIXED, 0, 0);
    return;
  }
  // Write the first message using the bullet-proof write.
  if (13 != write(2, "ASAN:SIGSEGV\n", 13)) abort();
  uintptr_t pc, sp, bp, ax;
  GetPcSpBpAx(context, &pc, &sp, &bp, &ax);

  Printf("==%d== ERROR: AddressSanitizer crashed on unknown address "PP""
         " (pc %p sp %p bp %p ax %p T%d)\n",
         getpid(), addr, pc, sp, bp, ax, AsanThread::GetCurrent()->tid());
  Printf("AddressSanitizer can not provide additional info. ABORTING\n");
  GET_STACK_TRACE_WITH_PC_AND_BP(kStackTraceMax, false, pc, bp);
  stack.PrintStack();
  __asan_show_stats_and_abort();
}

void __asan_report_error(uintptr_t pc, uintptr_t bp, uintptr_t sp,
                         uintptr_t addr, bool is_write, size_t access_size) {
  // Do not print more than one report, otherwise they will mix up.
  static int num_calls = 0;
  if (AtomicInc(&num_calls) > 1) return;

  Printf("=================================================================\n");
  const char *bug_descr = "unknown-crash";
  if (AddrIsInMem(addr)) {
    uint8_t *shadow_addr = (uint8_t*)MemToShadow(addr);
    uint8_t shadow_byte = shadow_addr[0];
    if (shadow_byte > 0 && shadow_byte < 128) {
      // we are in the partial right redzone, look at the next shadow byte.
      shadow_byte = shadow_addr[1];
    }
    switch (shadow_byte) {
      case kAsanHeapLeftRedzoneMagic:
      case kAsanHeapRightRedzoneMagic:
        bug_descr = "heap-buffer-overflow";
        break;
      case kAsanHeapFreeMagic:
        bug_descr = "heap-use-after-free";
        break;
      case kAsanStackLeftRedzoneMagic:
        bug_descr = "stack-buffer-underflow";
        break;
      case kAsanStackMidRedzoneMagic:
      case kAsanStackRightRedzoneMagic:
      case kAsanStackPartialRedzoneMagic:
        bug_descr = "stack-buffer-overflow";
        break;
      case kAsanStackAfterReturnMagic:
        bug_descr = "stack-use-after-return";
        break;
      case kAsanGlobalRedzoneMagic:
        bug_descr = "global-buffer-overflow";
        break;
    }
  }

  Printf("==%d== ERROR: AddressSanitizer %s on address "
         ""PP" at pc 0x%lx bp 0x%lx sp 0x%lx\n",
         getpid(), bug_descr, addr, pc, bp, sp);

  Printf("%s of size %d at "PP" thread T%d\n",
          access_size ? (is_write ? "WRITE" : "READ") : "ACCESS",
          access_size, addr, AsanThread::GetCurrent()->tid());

  if (__asan_flag_debug) {
    PrintBytes("PC: ", (uintptr_t*)pc);
  }

  GET_STACK_TRACE_WITH_PC_AND_BP(kStackTraceMax,
                                 false,  // __asan_flag_fast_unwind,
                                 pc, bp);
  stack.PrintStack();

  CHECK(AddrIsInMem(addr));

  DescribeAddress(addr, access_size);

  uintptr_t shadow_addr = MemToShadow(addr);
  Printf("==%d== ABORTING\n", getpid());
  __asan_stats.PrintStats();
  Printf("Shadow byte and word:\n");
  Printf("  "PP": %x\n", shadow_addr, *(unsigned char*)shadow_addr);
  uintptr_t aligned_shadow = shadow_addr & ~(kWordSize - 1);
  PrintBytes("  ", (uintptr_t*)(aligned_shadow));
  Printf("More shadow bytes:\n");
  PrintBytes("  ", (uintptr_t*)(aligned_shadow-4*kWordSize));
  PrintBytes("  ", (uintptr_t*)(aligned_shadow-3*kWordSize));
  PrintBytes("  ", (uintptr_t*)(aligned_shadow-2*kWordSize));
  PrintBytes("  ", (uintptr_t*)(aligned_shadow-1*kWordSize));
  PrintBytes("=>", (uintptr_t*)(aligned_shadow+0*kWordSize));
  PrintBytes("  ", (uintptr_t*)(aligned_shadow+1*kWordSize));
  PrintBytes("  ", (uintptr_t*)(aligned_shadow+2*kWordSize));
  PrintBytes("  ", (uintptr_t*)(aligned_shadow+3*kWordSize));
  PrintBytes("  ", (uintptr_t*)(aligned_shadow+4*kWordSize));
  abort();
}

static void     ASAN_OnSIGILL(int, siginfo_t *siginfo, void *context) {
  // Write the first message using the bullet-proof write.
  if (12 != write(2, "ASAN:SIGILL\n", 12)) abort();
  uintptr_t pc, sp, bp, ax;
  GetPcSpBpAx(context, &pc, &sp, &bp, &ax);

  uintptr_t addr = ax;

  uint8_t *insn = (uint8_t*)pc;
  CHECK(insn[0] == 0x0f && insn[1] == 0x0b);  // ud2
  unsigned access_size_and_type = insn[2] - 0x50;
  CHECK(access_size_and_type < 16);
  bool is_write = access_size_and_type & 8;
  int access_size = 1 << (access_size_and_type & 7);
  __asan_report_error(pc, bp, sp, addr, is_write, access_size);
}

// exported functions
#define ASAN_REPORT_ERROR(type, is_write, size) \
extern "C" void __asan_report_ ## type ## size(uintptr_t addr)   \
  __attribute__((visibility("default")));                        \
extern "C" void __asan_report_ ## type ## size(uintptr_t addr) { \
  GET_BP_PC_SP;                                                  \
  __asan_report_error(pc, bp, sp, addr, is_write, size);  \
}

ASAN_REPORT_ERROR(load, false, 1)
ASAN_REPORT_ERROR(load, false, 2)
ASAN_REPORT_ERROR(load, false, 4)
ASAN_REPORT_ERROR(load, false, 8)
ASAN_REPORT_ERROR(load, false, 16)
ASAN_REPORT_ERROR(store, true, 1)
ASAN_REPORT_ERROR(store, true, 2)
ASAN_REPORT_ERROR(store, true, 4)
ASAN_REPORT_ERROR(store, true, 8)
ASAN_REPORT_ERROR(store, true, 16)


// -------------------------- Init ------------------- {{{1
static int64_t IntFlagValue(const char *flags, const char *flag,
                            int64_t default_val) {
  if (!flags) return default_val;
  const char *str = strstr(flags, flag);
  if (!str) return default_val;
  return atoll(str + __asan::internal_strlen(flag));
}

static void asan_atexit() {
  Printf("AddressSanitizer exit stats:\n");
  __asan_stats.PrintStats();
}

void __asan_init() {
  if (__asan_inited) return;
  __asan_init_is_running = true;
  asan_out = stderr;

  // flags
  const char *options = getenv("ASAN_OPTIONS");
  __asan_flag_malloc_context_size =
      IntFlagValue(options, "malloc_context_size=", kMallocContextSize);
  CHECK(__asan_flag_malloc_context_size <= kMallocContextSize);

  __asan_flag_v = IntFlagValue(options, "verbosity=", 0);

  __asan_flag_redzone = IntFlagValue(options, "redzone=", 128);
  CHECK(__asan_flag_redzone >= 32);
  CHECK((__asan_flag_redzone & (__asan_flag_redzone - 1)) == 0);

  __asan_flag_atexit = IntFlagValue(options, "atexit=", 0);
  __asan_flag_poison_shadow = IntFlagValue(options, "poison_shadow=", 1);
  __asan_flag_report_globals = IntFlagValue(options, "report_globals=", 1);
  __asan_flag_lazy_shadow = IntFlagValue(options, "lazy_shadow=", 0);
  __asan_flag_handle_segv = IntFlagValue(options, "handle_segv=",
                                         ASAN_NEEDS_SEGV);
  __asan_flag_stats = IntFlagValue(options, "stats=", 0);
  __asan_flag_symbolize = IntFlagValue(options, "symbolize=", 1);
  __asan_flag_demangle = IntFlagValue(options, "demangle=", 1);
  __asan_flag_debug = IntFlagValue(options, "debug=", 0);
  __asan_flag_fast_unwind = IntFlagValue(options, "fast_unwind=", 1);
  __asan_flag_mt = IntFlagValue(options, "mt=", 1);
  __asan_flag_replace_str = IntFlagValue(options, "replace_str=", 1);
  __asan_flag_replace_intrin = IntFlagValue(options, "replace_intrin=", 0);

  if (__asan_flag_atexit) {
    atexit(asan_atexit);
  }

  __asan_flag_quarantine_size =
      IntFlagValue(options, "quarantine_size=", 1UL << 28);

  // interceptors
  __asan_interceptors_init();

  __asan_replace_system_malloc();

  INTERCEPT_FUNCTION(sigaction);
  INTERCEPT_FUNCTION(signal);
  INTERCEPT_FUNCTION(longjmp);
  INTERCEPT_FUNCTION(_longjmp);
#ifndef __APPLE__
  // siglongjmp for x86 looks as follows:
  // 2f8a8:       8b 44 24 04             mov    0x4(%esp),%eax
  // 2f8ac:       83 78 48 00             cmpl   $0x0,0x48(%eax)
  // 2f8b0:       0f 85 76 ba 13 00       jne    16b32c <___udivmoddi4+0x19ec>
  // 2f8b6:       eb 3f                   jmp    2f8f7 <_longjmp+0x3f>
  // Instead of handling those instructions in mach_override we assume that
  // patching longjmp is sufficient.
  // TODO(glider): need a test for this.
  INTERCEPT_FUNCTION(siglongjmp);
#endif
  INTERCEPT_FUNCTION(__cxa_throw);
  INTERCEPT_FUNCTION(pthread_create);

  struct sigaction sigact;

  if (__asan_flag_handle_segv) {
    // Set the SIGSEGV handler.
    __asan::real_memset(&sigact, 0, sizeof(sigact));
    sigact.sa_sigaction = ASAN_OnSIGSEGV;
    sigact.sa_flags = SA_SIGINFO;
    CHECK(0 == __asan::real_sigaction(SIGSEGV, &sigact, 0));

#ifdef __APPLE__
    // Set the SIGBUS handler. Mac OS may generate either SIGSEGV or SIGBUS.
    __asan::real_memset(&sigact, 0, sizeof(sigact));
    sigact.sa_sigaction = ASAN_OnSIGSEGV;
    sigact.sa_flags = SA_SIGINFO;
    CHECK(0 == __asan::real_sigaction(SIGBUS, &sigact, 0));
#endif
  } else {
    CHECK(!__asan_flag_lazy_shadow);
  }

  // Set the SIGILL handler.
  __asan::real_memset(&sigact, 0, sizeof(sigact));
  sigact.sa_sigaction = ASAN_OnSIGILL;
  sigact.sa_flags = SA_SIGINFO;
  CHECK(0 == __asan::real_sigaction(SIGILL, &sigact, 0));

  if (__asan_flag_v) {
    Printf("|| `["PP", "PP"]` || HighMem    ||\n", kHighMemBeg, kHighMemEnd);
    Printf("|| `["PP", "PP"]` || HighShadow ||\n",
           kHighShadowBeg, kHighShadowEnd);
    Printf("|| `["PP", "PP"]` || ShadowGap  ||\n",
           kShadowGapBeg, kShadowGapEnd);
    Printf("|| `["PP", "PP"]` || LowShadow  ||\n",
           kLowShadowBeg, kLowShadowEnd);
    Printf("|| `["PP", "PP"]` || LowMem     ||\n", kLowMemBeg, kLowMemEnd);
    Printf("MemToShadow(shadow): "PP" "PP" "PP" "PP"\n",
           MEM_TO_SHADOW(kLowShadowBeg),
           MEM_TO_SHADOW(kLowShadowEnd),
           MEM_TO_SHADOW(kHighShadowBeg),
           MEM_TO_SHADOW(kHighShadowEnd));
    Printf("red_zone=%ld\n", __asan_flag_redzone);
    Printf("malloc_context_size=%ld\n", (int)__asan_flag_malloc_context_size);
    Printf("fast_unwind=%d\n", (int)__asan_flag_fast_unwind);

    Printf("SHADOW_SCALE: %lx\n", SHADOW_SCALE);
    Printf("SHADOW_GRANULARITY: %lx\n", SHADOW_GRANULARITY);
    Printf("SHADOW_OFFSET: %lx\n", SHADOW_OFFSET);
    CHECK(SHADOW_SCALE >= 3 && SHADOW_SCALE <= 7);
  }

  if (__WORDSIZE == 64) {
    // Disable core dumper -- it makes little sense to dump 16T+ core.
    struct rlimit nocore;
    nocore.rlim_cur = 0;
    nocore.rlim_max = 0;
    setrlimit(RLIMIT_CORE, &nocore);
  }

  {
    if (!__asan_flag_lazy_shadow) {
      if (kLowShadowBeg != kLowShadowEnd) {
        // mmap the low shadow plus one page.
        mmap_range(kLowShadowBeg - kPageSize, kLowShadowEnd, "LowShadow");
      }
      // mmap the high shadow.
      mmap_range(kHighShadowBeg, kHighShadowEnd, "HighShadow");
    }
    // protect the gap
    protect_range(kShadowGapBeg, kShadowGapEnd);
  }

  // On Linux AsanThread::ThreadStart() calls malloc() that's why __asan_inited
  // should be set to 1 prior to initializing the threads.
  __asan_inited = 1;
  __asan_init_is_running = false;

  AsanThread::Init();
  AsanThread::GetMain()->ThreadStart();

  if (__asan_flag_v) {
    Printf("==%d== AddressSanitizer r%s Init done ***\n",
           getpid(), ASAN_REVISION);
  }
}

void __asan_check_failed(const char *cond, const char *file, int line) {
  Printf("CHECK failed: %s at %s:%d\n", cond, file, line);
  PRINT_CURRENT_STACK();
  __asan_show_stats_and_abort();
}
