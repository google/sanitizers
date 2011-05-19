/* Copyright 2011 Google Inc.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

// This file is a part of AddressSanitizer, an address sanity checker.
// Author: Kostya Serebryany

#include "asan_rtl.h"
#include <stdint.h>
#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <execinfo.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <algorithm>
#include <sys/syscall.h>
#include <sys/ucontext.h>
#include <string>
#include <dlfcn.h>

using std::string;

#include "unwind.h"

#include "bfd_symbolizer/bfd_symbolizer.h"

static void PrintCurrentStack(uintptr_t pc = 0);

#define CHECK(cond) do { if (!(cond)) { \
  Printf("CHECK failed: %s at %s:%d\n", #cond, __FILE__, __LINE__);\
  PrintCurrentStack(); \
  ShowStatsAndAbort(); \
}}while(0)

__attribute__((constructor)) static void asan_init();

// -------------------------- Flags ------------------------- {{{1
static const size_t kStackTraceMax = 64;
static const size_t kMallocContextSize = 30;
static int    F_v;
static size_t F_malloc_context_size = kMallocContextSize;
static size_t F_red_zone_words;  // multiple of 8
static size_t F_delay_queue_size;
static int    F_print_maps;
static int    F_print_malloc_lists;
static int    F_abort_after_first;
static int    F_atexit;
static uintptr_t F_large_malloc;
static bool   F_poison_shadow;
static int    F_stats;
static int    F_debug;
static int    F_symbolize;  // use in-process symbolizer
static int    F_demangle;
static bool   F_fast_unwind;

// -------------------------- Atomic ---------------- {{{1
int AtomicInc(int *a) {
  return __sync_add_and_fetch(a, 1);
}

int AtomicDec(int *a) {
  return __sync_add_and_fetch(a, -1);
}

// -------------------------- Printf ---------------- {{{1
static FILE *asan_out;

static void Printf(const char *format, ...) {
  va_list args;
  va_start(args, format);
  vfprintf(asan_out, format, args);
  fflush(asan_out);
  va_end(args);
}

// -------------------------- Build modes --------------------- {{{1
#ifndef ASAN_BYTE_TO_BYTE_SHADOW
# error must define ASAN_BYTE_TO_BYTE_SHADOW
#endif

#ifndef ASAN_IN_MEMORY_POISON
# define ASAN_IN_MEMORY_POISON 0
#endif

#ifndef ASAN_CROS
# define ASAN_CROS 0
#endif


// -------------------------- Mapping --------------------- {{{1
const size_t kWordSize = __WORDSIZE / 8;
const size_t kWordSizeInBits = 8 * kWordSize;
const size_t kPageSizeBits = 12;
const size_t kPageSize = 1UL << kPageSizeBits;

#if __WORDSIZE == 64
const size_t kPageClusterSizeBits = 8;
const size_t kPageClusterSize = 1UL << kPageClusterSizeBits;
const size_t kPossiblePageClustersBits = 46 - kPageClusterSizeBits - kPageSizeBits;
#else
const size_t kPageClusterSizeBits = 4;
const size_t kPageClusterSize = 1UL << kPageClusterSizeBits;
const size_t kPossiblePageClustersBits = 32 - kPageClusterSizeBits - kPageSizeBits;
#endif


/*
On 64-bit linux the address space is divided into 6 regions:<br>
The Mem regions, `LowMem` and `HighMem`,
are the regions where the application memory is mapped.<br>
The Shadow regions, `LowShadow` and `HighShadow`
are the shadow memory regions corresponding to
`LowMem` and `HighMem` respectively. <br>
The Bad regions, `LowBad` and `HighBad`, are unmapped regions.

|| `[0x0000000000000000, 0x0000008000000000)` || `LowMem`     ||
|| `[0x0000040000000000, 0x0000080000000000)` || `LowShadow`  ||
|| `[0x0000080000000000, 0x0000100000000000)` || `LowBad`     ||
|| `[0x00001f0000000000, 0x0000200000000000)` || `HighShadow` ||
|| `[0x00003e0000000000, 0x0000400000000000)` || `HighBad`    ||
|| `[0x00007f0000000000, 0x0000800000000000)` || `HighMem`    ||

Transforming between Mem and Shadow addresses:
{{{
  kLowShadowMask  = 0x0000040000000000;
  kHighShadowMask = 0x0000600000000000;
  Shadow = Mem | kLowShadowMask & ~kHighShadowMask;
  Mem = (Shadow < kLowShadowMask *2)
           ? (Shadow & ~kLowShadowMask)
           : (Shadow | kHighShadowMask)
}}}

Transforming between Shadow and Bad addresses:
{{{
  Bad = Shadow << 1;
  Shadow = Bad >> 1;
}}}

Every memory access in the compiled program is instrumented like this:

{{{
// BEFORE
void write(int *a) {
  *a = 0;
}
}}}
{{{
// AFTER
void write(int *a) {
  uintptr_t shadow_address = (uintptr_t)a;
  shadow_address |=  kLowShadowMask;
  shadow_address &= ~kHighShadowMask;
  shadow_address += 64; // to avoid cache bank conflicts.
  if (*(int*)(shadow_address)) {
    char *bad_address = (char*)(shadow_address * 4);
    *bad = 0;
  }
  *a = 0;
}
}}}

Regular Linux 64-bit address space, compact shadow (1 byte per qword).

|| `[0x0000000000000000, 0x0000008000000000)` || `LowMem`     ||
|| `[0x0000100000000000, 0x0000101000000000)` || `LowShadow`  ||
|| `[0x0000200000000000, 0x0000202000000000)` || `LowBad`     ||
|| `[0x00001fe000000000, 0x00001fffffffffff]` || `HighShadow` ||
|| `[0x00002fc000000000, 0x00003fffffffffff]` || `HighBad`    ||
|| `[0x00007f0000000000, 0x00007fffffffffff]` || `HighMem`    ||

Shadow = (Mem >> 3) | 0x0000100000000000;
Bad = Shadow * 2


Regular Linux 32-bit address space:

|| `[0x00000000, 0x1fffffff]` || `LowMem`           ||
|| `[0x20000000, 0x23ffffff]` || `LowShadow`        ||
|| `[0x30000000, 0x3fffffff]` || `HighShadow`       ||
|| `[0x40000000, 0x47ffffff]` || `LowBad`           ||
|| `[0x60000000, 0x7fffffff]` || `HighBad`          ||
|| `[0x80000000, 0xffffffff]` || `HighMem`          ||

Shadow = (Mem >> 3) | 0x20000000;
Mem = (Shadow & ~0x20000000) << 3
Bad = Shadow * 2

CrOS (32-bit):

|| `[0x00000000, 0x1fffffff]` || `LowMem`           ||
|| `[0x20000000, 0x23ffffff]` || `LowShadow`        ||
|| `[0x26000000, 0x2fffffff]` || `HighShadow`       ||
|| `[0x30000000, 0x7fffffff]` || `HighMem`          ||
|| `[0x80000000, 0xffffffff]` || `Bad`              ||

Shadow = (Mem >> 3) | 0x20000000;
Mem = (Shadow & ~0x20000000) << 3
Bad = Shadow * 4;

*/

#if __WORDSIZE == 64
const size_t kLowMemEnd     = (1UL << 39);

const size_t kFullLowShadowBeg = kFullLowShadowMask;
const size_t kFullLowShadowEnd = kFullLowShadowMask << 1;

const size_t kHighMemBeg     = 0x0000700000000000UL;
const size_t kHighMemEnd     = 0x00007fffffffffffUL;

const size_t kFullHighShadowBeg  = 0x0000100000000000UL;
const size_t kFullHighShadowEnd  = 0x00001fffffffffffUL;

const size_t kPoisonedByte = 0xb8;
#define BYTE_TO_WORD(b) \
    ((b+0))|((b+1)<<8)|((b+2)<<16)|((b+3)<<24)|\
     ((b+4)<<32)|((b+5)<<40)|((b+6)<<48)|((b+7)<<56)
const size_t kPoisonedWordLeftRedZone =  BYTE_TO_WORD(0xa0UL);
const size_t kPoisonedWordRightRedZone = BYTE_TO_WORD(0xb0UL);
const size_t kPoisonedWordOnFree =       BYTE_TO_WORD(0xd0UL);

const size_t kCompactShadowMask  = kCompactShadowMask64;

#define PP "0x%016lx"

#else  // __WORDSIZE == 32

#if ASAN_CROS
const size_t kCompactShadowMask  = kCROSShadowMask32;
const size_t kHighMemBeg     = 0x30000000;
const size_t kHighMemEnd     = 0x7fffffff;
#else
const size_t kCompactShadowMask  = kCompactShadowMask32;
const size_t kHighMemBeg     = 0x80000000;
const size_t kHighMemEnd     = 0xffffffff;
#endif
const size_t kLowMemEnd     = kCompactShadowMask;


#define PP "0x%08lx"

#endif  // __WORDSIZE

#if !ASAN_BYTE_TO_BYTE_SHADOW
const size_t kLowShadowBeg   = kCompactShadowMask;
const size_t kLowShadowEnd   = (kLowMemEnd >> 3) | kCompactShadowMask;
const size_t kHighShadowBeg  = (kHighMemBeg >> 3) | kCompactShadowMask;
const size_t kHighShadowEnd  = (kHighMemEnd >> 3) | kCompactShadowMask;
#else
const size_t kLowShadowBeg   = kFullLowShadowBeg;
const size_t kLowShadowEnd   = kFullLowShadowEnd;
const size_t kHighShadowBeg  = kFullHighShadowBeg;
const size_t kHighShadowEnd  = kFullHighShadowEnd;
#endif

// -------------------------- Globals --------------------- {{{1
static int asan_inited;

static uintptr_t
  mapped_clusters[(1UL << kPossiblePageClustersBits) / kWordSizeInBits];
static pthread_mutex_t shadow_lock;

int __asan_byte_to_byte_shadow = ASAN_BYTE_TO_BYTE_SHADOW;


// -------------------------- Interceptors ---------------- {{{1
typedef int (*sigaction_f)(int signum, const struct sigaction *act,
                           struct sigaction *oldact);
typedef sig_t (*signal_f)(int signum, sig_t handler);
typedef void* (*mmap_f)(void *start, size_t length,
                            int prot, int flags,
                            int fd, off_t offset);

typedef void *(*malloc_f)(size_t);
typedef void *(*realloc_f)(void*, size_t);
typedef void  (*free_f)(void*);
typedef int (*pthread_create_f)(pthread_t *thread, const pthread_attr_t *attr,
                              void *(*start_routine) (void *), void *arg);

static sigaction_f      real_sigaction;
static signal_f         real_signal;
static mmap_f           real_mmap;
static malloc_f         real_malloc;
static realloc_f        real_realloc;
static free_f           real_free;
static pthread_create_f real_pthread_create;

// -------------------------- Stats ---------------- {{{1
struct Stats {
  size_t low_shadow_maps;
  size_t high_shadow_maps;
  size_t mallocs;
  size_t malloced;
  size_t malloced_redzones;
  size_t frees;
  size_t freed;
  size_t real_frees;
  size_t really_freed;
  size_t reallocs;
  size_t realloced;
  size_t freed_since_last_stats;

  void PrintStats() {
    Printf("Stats: %ldM malloced (%ldM for red zones) by %ld calls\n",
           malloced>>20, malloced_redzones>>20, mallocs);
    Printf("Stats: %ldM realloced by %ld calls\n", realloced>>20, reallocs);
    Printf("Stats: %ldM freed by %ld calls\n", freed>>20, frees);
    Printf("Stats: %ldM really freed by %ld calls\n",
           really_freed>>20, real_frees);
    Printf("Stats: %ldM of shadow memory allocated in %ld clusters\n"
           "             (%ldM each, %ld low and %ld high)\n",
           ((low_shadow_maps + high_shadow_maps) * kPageClusterSize * kPageSize)>>20,
           low_shadow_maps + high_shadow_maps,
           (kPageClusterSize * kPageSize) >> 20,
           low_shadow_maps, high_shadow_maps);
  }
};

static Stats stats;


// -------------------------- Misc ---------------- {{{1

class ScopedLock {
 public:
  ScopedLock(pthread_mutex_t *mu) : mu_(mu) {
    pthread_mutex_lock(mu_);
  }
  ~ScopedLock() {
    pthread_mutex_unlock(mu_);
  }
 private:
  pthread_mutex_t *mu_;
};

static void AsanAbort() {
  if (asan_out != stderr) {
    pclose(asan_out);
  }
  abort();
}

static void ShowStatsAndAbort() {
  stats.PrintStats();
  AsanAbort();
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

#if ASAN_IN_MEMORY_POISON
uintptr_t __asan_addr;
uint8_t __asan_aux;
#endif



static __thread bool tl_need_real_malloc;

// -------------------------- Mapping ---------------- {{{1

static bool AddrIsInLowMem(uintptr_t a) {
  return a < kLowMemEnd;
}

static bool AddrIsInLowShadow(uintptr_t a) {
  return a >= kLowShadowBeg && a < kLowShadowEnd;
}

static bool AddrIsInHighMem(uintptr_t a) {
  return a >= kHighMemBeg && a <= kHighMemEnd;
}

static bool AddrIsInHighShadow(uintptr_t a) {
  return a >= kHighShadowBeg && a < kHighShadowEnd;
}

static bool AddrIsInMem(uintptr_t a) {
  return AddrIsInLowMem(a) || AddrIsInHighMem(a);
}

static bool AddrIsInShadow(uintptr_t a) {
  return AddrIsInLowShadow(a) || AddrIsInHighShadow(a);
}

static uintptr_t MemToShadow(uintptr_t p) {
  CHECK(AddrIsInMem(p));
#if !ASAN_BYTE_TO_BYTE_SHADOW
  return (p >> 3) | kCompactShadowMask;
#else
  uintptr_t shadow = (p | kFullLowShadowMask) & (~kFullHighShadowMask);
  return shadow + kBankPadding;
#endif
}

static uintptr_t ShadowToMem(uintptr_t shadow) {
#if !ASAN_BYTE_TO_BYTE_SHADOW
    return (shadow & ~kCompactShadowMask) << 3;
#else
  uintptr_t mem = shadow - kBankPadding;
  if (mem > kLowShadowEnd)
    mem |= kFullHighShadowMask;
  else
    mem &= ~(kFullLowShadowMask);
  return mem;
#endif
}

static uintptr_t BadToShadow(uintptr_t bad) {
#if ASAN_CROS
  return bad >> 2;
#elif !ASAN_BYTE_TO_BYTE_SHADOW
  return bad >> 1;
#else
  return (bad >> 1) + kBankPadding;
#endif
}

// ----------------------- ProcSelfMaps ----------------------------- {{{1
class ProcSelfMaps {
 public:
  void Init() {
    int maps = open("/proc/self/maps", O_RDONLY);
    if (maps) {
      size_t size = read(maps, proc_self_maps, kMaxProcSelfMapsSize);
      if (F_v >= 1) {
        Printf("read %ld bytes from /proc/self/maps\n", size);
      }
      proc_self_maps[size] = 0;
      close(maps);
    }
    const char *line_beg = proc_self_maps;

    map_size_ = 0;
    while (line_beg && *line_beg) {
      CHECK(map_size_ < kMaxProcSelfMapsSize);
      Mapping &mapping = memory_map[map_size_];
      if (F_v >= 2) {
        char buff[1024];
        copy_until_new_line(line_beg, buff, sizeof(buff));
        Printf("*** |%s|\n", buff);
      }
      char r = 0, w = 0, x = 0, p = 0;
      sscanf(line_beg, "%lx-%lx %c%c%c%c",
             (unsigned long*)&mapping.beg, (unsigned long*)&mapping.end,
             &r, &w, &x, &p);
      for (const char *s = line_beg; *s && *s != '\n'; s++) {
        if (*s == '/') {
          mapping.name_beg = s;
          break;
        }
      }
      if (mapping.name_beg && x == 'x') {
        map_size_++;
        if (F_v >= 1) {
          char buff[1024];
          copy_until_new_line(mapping.name_beg, buff, sizeof(buff));
          Printf("[%lx-%lx) %s\n", mapping.beg, mapping.end, buff);
        }
      }
      line_beg = strchr(line_beg, '\n');
      if (line_beg) line_beg++;
    }

  }

  void Print() {
    Printf("%s\n", proc_self_maps);
  }

  void PrintPc(uintptr_t pc, int idx) {
    const int kLen = 1024;
    char func[kLen+1] = "",
         file[kLen+1] = "",
         module[kLen+1] = "";
    int line = 0;
    int offset = 0;

    if (F_symbolize) {
      tl_need_real_malloc = true;
      int opt = bfds_opt_none;
      if (idx == 0)
        opt |= bfds_opt_update_libs;
      if (F_demangle == 1) opt |= bfds_opt_demangle;
      if (F_demangle == 2) opt |= bfds_opt_demangle_params;
      if (F_demangle == 3) opt |= bfds_opt_demangle_verbose;
      int res = bfds_symbolize((void*)pc,
                               (bfds_opts_e)opt,
                               func, kLen,
                               module, kLen,
                               file, kLen,
                               &line,
                               &offset);
      tl_need_real_malloc = false;
      if (res == 0) {
        Printf("    #%d 0x%lx in %s %s:%d\n", idx, pc, func, file, line);
        return;
      }
      // bfd failed
    }

    for (size_t i = 0; i < map_size_; i++) {
      Mapping &m = memory_map[i];
      if (pc >= m.beg && pc < m.end) {
        char buff[kLen + 1];
        uintptr_t offset = pc - m.beg;
        if (i == 0) offset = pc;
        copy_until_new_line(m.name_beg, buff, kLen);
        Printf("    #%d 0x%lx (%s+0x%lx)\n", idx, pc, buff, offset);
        return;
      }
    }
    Printf("  #%d 0x%lx\n", idx, pc);
  }

 private:
  void copy_until_new_line(const char *str, char *dest, size_t max_size) {
    size_t i = 0;
    for (; str[i] && str[i] != '\n' && i < max_size - 1; i++){
      dest[i] = str[i];
    }
    dest[i] = 0;
  }


  struct Mapping {
    uintptr_t beg, end;
    const char *name_beg;
  };
  static const size_t kMaxNumMapEntries = 4096;
  static const size_t kMaxProcSelfMapsSize = 1 << 20;
  char proc_self_maps[kMaxProcSelfMapsSize];
  size_t map_size_;
  Mapping memory_map[kMaxNumMapEntries];
};

static ProcSelfMaps proc_self_maps;

// ---------------------- Stack Trace and Thread ------------------------- {{{1
struct StackTrace {
  size_t size;
  size_t max_size;
  uintptr_t trace[kStackTraceMax];
}; 

static void PrintStack(uintptr_t *addr, size_t size) {
  for (size_t i = 0; i < size && addr[i]; i++) {
    uintptr_t pc = addr[i];
    string img, rtn, file;
    int line;
    // PcToStrings(pc, true, &img, &rtn, &file, &line);
    proc_self_maps.PrintPc(pc, i);
    // Printf("  #%ld 0x%lx %s\n", i, pc, rtn.c_str());
    if (rtn == "main()") break;
  }
}

static void PrintStack(StackTrace &stack) {
  PrintStack(stack.trace, stack.size);
}

struct AsanThread {

  AsanThread(void *(*start_routine) (void *), void *arg, StackTrace *stack)
    : start_routine_(start_routine),
      arg_(arg), 
      announced_(false),
      tid_(AtomicInc(&n_threads_) - 1),
      refcount_(1) {
    if (stack) {
      stack_ = *stack;
    }
    if (tid_ == 0) {
      pthread_mutex_init(&mu_, 0);
      live_threads_ = next_ = prev_ = this;
    }
  }

  void *ThreadStart() {
    {
      tl_need_real_malloc = true;
      pthread_attr_t attr;
      CHECK (pthread_getattr_np(pthread_self(), &attr) == 0);
      size_t stacksize = 0;
      void *stackaddr = NULL;
      pthread_attr_getstack(&attr, &stackaddr, &stacksize);
      pthread_attr_destroy(&attr);
      stack_top_ = (uintptr_t)stackaddr + stacksize;
      stack_bottom_ = (uintptr_t)stackaddr;
      CHECK(AddrIsInStack((uintptr_t)&attr));
      tl_need_real_malloc = false;
    }
    if (F_v == 1) {
      Printf ("T%d: stack ["PP","PP") size 0x%lx\n",
              tid_, stack_bottom_, stack_top_, stack_top_ - stack_bottom_);
    }
    CHECK(AddrIsInMem(stack_bottom_));
    CHECK(AddrIsInMem(stack_top_));

    { // Insert this thread into live_threads_
      ScopedLock lock(&mu_);
      this->next_ = live_threads_;
      this->prev_ = live_threads_->prev_;
      this->prev_->next_ = this;
      this->next_->prev_ = this;
    }

    if (!start_routine_) return 0;

    void *res = start_routine_(arg_);

    { // Remove this from live_threads_
      ScopedLock lock(&mu_);
      AsanThread *prev = this->prev_;
      AsanThread *next = this->next_;
      prev->next_ = next_;
      next->prev_ = prev_;
    }
    Unref();
    return res;
  }

  AsanThread *Ref() {
    AtomicInc(&refcount_);
    return this;
  }

  void Unref() {
    CHECK(refcount_ > 0);
    if (AtomicDec(&refcount_) == 0)
      real_free(this);
  }

  void Announce() {
    if (tid_ == 0) return; // no need to announce the main thread.
    if (!announced_) {
      announced_ = true;
      Printf("Thread T%d created here:\n", tid_);
      PrintStack(stack_);
    }
  }

  uintptr_t stack_top() { return stack_top_; }
  uintptr_t stack_bottom() { return stack_bottom_; }
  int tid() { return tid_; }

  uintptr_t AddrIsInStack(uintptr_t addr) {
    return addr >= stack_bottom_ && addr < stack_top_;
  }

  static AsanThread *FindThreadByStackAddress(uintptr_t addr) {
    ScopedLock lock(&mu_);
    AsanThread *t = live_threads_;
    do {
      if (t->AddrIsInStack(addr)) {
        return t;
      }
      t = t->next_;
    } while (t != live_threads_);
    return 0;
  }

 private:
  void *(*start_routine_) (void *);
  void *arg_;
  StackTrace stack_;
  uintptr_t  stack_top_;
  uintptr_t  stack_bottom_;
  int        tid_;
  bool       announced_;
  int        refcount_;

  AsanThread *next_;
  AsanThread *prev_;

  static AsanThread *live_threads_;
  static int n_threads_;
  static pthread_mutex_t mu_;
};

int AsanThread::n_threads_;
AsanThread *AsanThread::live_threads_;
pthread_mutex_t AsanThread::mu_;
static __thread AsanThread *tl_current_thread;

static _Unwind_Reason_Code Unwind_Trace (struct _Unwind_Context *ctx, void *param) {
  StackTrace *b = (StackTrace*)param;
  CHECK(b->size < b->max_size);
  b->trace[b->size] = _Unwind_GetIP(ctx);
  // Printf("ctx: %p ip: %lx\n", ctx, b->buff[b->cur]);
  b->size++;
  if (b->size == b->max_size) return _URC_NORMAL_STOP;
  return _URC_NO_REASON;
}

#define GET_CALLER_PC() (uintptr_t)__builtin_return_address(0)
#define GET_CURRENT_FRAME() (uintptr_t*)__builtin_frame_address(0)

__attribute__((noinline))
static void FastUnwindStack(uintptr_t *frame, StackTrace *stack) {
  stack->trace[stack->size++] = GET_CALLER_PC();
  if (!tl_current_thread) return;
  uintptr_t *prev_frame = frame;
  uintptr_t *top = (uintptr_t*)tl_current_thread->stack_top();
  while (frame >= prev_frame && 
         frame < top &&
         stack->size < stack->max_size) {
    //Printf("FastUnwindStack[%d]:  "PP" "PP" "PP"\n", 
    //       (int)stack->size,
    //       frame, prev_frame, top);
    uintptr_t pc = frame[1];
    stack->trace[stack->size++] = pc;
    prev_frame = frame;
    frame = (uintptr_t*)frame[0];
  }
}

#define GET_STACK_TRACE_HERE(max_s, fast_unwind)  \
  StackTrace stack;                               \
  if ((max_s) <= 1) {                             \
    stack.size = 1;                               \
    stack.trace[0] = GET_CALLER_PC();             \
  } else {                                        \
    stack.max_size = max_s;                       \
    stack.size  = 0;                              \
    if (fast_unwind)   \
      FastUnwindStack(GET_CURRENT_FRAME(), &stack); \
    else                                          \
      _Unwind_Backtrace(Unwind_Trace, &stack);    \
    if (stack.size >= 2) {                        \
      CHECK(stack.trace[1] == GET_CALLER_PC());   \
    }                                             \
  }                                               \

#define GET_STACK_TRACE_HERE_FOR_MALLOC         \
  GET_STACK_TRACE_HERE(F_malloc_context_size, F_fast_unwind)

#define GET_STACK_TRACE_HERE_FOR_FREE(ptr) \
  Ptr *__ptr_to_free = (Ptr*)((uintptr_t*)(ptr) - F_red_zone_words); \
  size_t __stack_size_for_free = (ptr)                               \
    ? __ptr_to_free->FreeStackSize() : 0;                            \
  GET_STACK_TRACE_HERE(__stack_size_for_free, F_fast_unwind)


void PrintCurrentStack(uintptr_t pc) {
  GET_STACK_TRACE_HERE(kStackTraceMax, /*fast unwind*/false);
  CHECK(stack.size >= 2);
  int skip_frames = 1;
  if (pc) {
    // find this pc, should be somewehre around 3-rd frame
    for (int i = skip_frames; i < stack.size; i++) {
      if (stack.trace[i] == pc) {
        skip_frames = i;
        break;
      }
    }
  }
  PrintStack(stack.trace + skip_frames, stack.size - skip_frames);
}

static void *asan_thread_start(void *arg) {
  tl_current_thread = (AsanThread*)arg;
  return tl_current_thread->ThreadStart();
}

// ---------------------- AddressSanitizer malloc -------------------- {{{1
static void OutOfMemoryMessage(const char *mem_type, size_t size) {
  Printf("==%d== ERROR: AddressSanitizer failed to allocate "
         "0x%lx (%ld) bytes of %s\n",
         getpid(), size, size, mem_type);
}

//static inline void* my_mmap(void *start, size_t length,
//                            int prot, int flags,
//                            int fd, off_t offset) {
//#if __WORDSIZE == 64
//  return (void *)syscall(SYS_mmap, start, length, prot, flags, fd, offset);
//#else
//  return (void *)syscall(SYS_mmap2, start, length, prot, flags, fd, offset);
//#endif
//}

static char *mmap_pages(size_t start_page, size_t n_pages, const char *mem_type) {
  void *res = real_mmap((void*)start_page, kPageSize * n_pages,
                   PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANON | MAP_FIXED, 0, 0);
  // Printf("%p => %p\n", (void*)start_page, res);
  char *ch = (char*)res;
  if (res == (void*)-1L) {
    OutOfMemoryMessage(mem_type, n_pages * kPageSize);
    ShowStatsAndAbort();
  }
  CHECK(res == (void*)start_page);
  return ch;
}

static char *mmap_low_shadow(size_t start_page, size_t n_pages) {
  CHECK(AddrIsInLowShadow(start_page));
  stats.low_shadow_maps++;
  return mmap_pages(start_page, n_pages, "low shadow memory");
}

static char *mmap_high_shadow(size_t start_page, size_t n_pages) {
  CHECK(AddrIsInHighShadow(start_page));
  stats.high_shadow_maps++;
  return mmap_pages(start_page, n_pages, "high shadow memory");
}

struct Ptr {
  uint32_t magic;
  uint32_t orig_libc_offset;
  size_t size;
  Ptr    *next;
  Ptr    *prev;
  AsanThread *malloc_thread;
  AsanThread *free_thread;

  static const uint32_t kMallocedMagic   = 0x45DEAA11;
  static const uint32_t kFreedMagic      = 0x94B06185;
  static const uint32_t kRealyFreedMagic = 0xDEAD1234;

  uintptr_t orig_libc_ptr() {
    return (uintptr_t)(this) - (uintptr_t)orig_libc_offset;
  }

  static size_t ReservedWords() { return sizeof(Ptr) / kWordSize; }

  size_t size_in_words() { return size_in_words(size); }
  size_t real_size_in_words() { return real_size_in_words(size); }

  uintptr_t rz1_beg() { return (uintptr_t)this; }
  uintptr_t rz1_end() { return rz1_beg() + F_red_zone_words * kWordSize; }
  uintptr_t beg()     {
    CHECK((rz1_end() % 8) == 0);
    return rz1_end(); 
  }
  uintptr_t end()     { return beg() + size; }
  uintptr_t rz2_beg() { return end(); }
  uintptr_t rz2_end() { return end() + F_red_zone_words * kWordSize; }
  void     *raw_ptr() { return (void*)beg(); }

  bool InRange(uintptr_t p) { return p >= rz1_beg() && p < rz2_end(); }
  bool InRz1(uintptr_t p)   { return p >= rz1_beg() && p < rz1_end(); }
  bool InRz2(uintptr_t p)   { return p >= rz2_beg() && p < rz2_end(); }
  bool InAllocated(uintptr_t p) { return p >= beg() && p < end(); }

  uintptr_t &at(size_t i) {
    return ((uintptr_t*)this)[i];
  }

  void PrintOneLine(const char *before = "", const char *after = "\n") {
    Printf(
            "%s["PP","PP"); red zones: ["PP","PP"), ["PP","PP");"
            " size=%ld (0x%lx)%s",
            before,
            beg(), end(), rz1_beg(), rz1_end(), rz2_beg(), rz2_end(),
            size, size,
            after);
  }

  void DescribeAddress(uintptr_t addr, size_t access_size) {
    CHECK(InRange(addr));
    Printf(" "PP" is the address located ", addr);
    if (InRz1(addr)) {
      Printf("%ld bytes to the left of region:\n", rz1_end() - addr);
    } else if (InRz2(addr) || InRz2(addr + access_size - 1)) {
      uintptr_t offset = addr - rz2_beg();
      if (addr < rz2_beg()) {
        CHECK(addr + access_size > rz2_beg());
        offset = 0;
      }
      Printf("%ld bytes to the right of region:\n", offset);
    } else {
      CHECK(InAllocated(addr));
      Printf("%ld bytes inside of region:\n", addr - beg());
    }
    Printf("["PP","PP") -- allocated memory of 0x%lx (%ld) bytes\n",
           beg(), end(), size, size);
    if (F_debug) {
      Printf("["PP","PP") -- left red zone\n", rz1_beg(), rz1_end());
      Printf("["PP","PP") -- right red zone\n", rz2_beg(), rz2_end());
    }
  }

  void CompactPoisonRegion(uintptr_t beg, uintptr_t end, uint64_t poison) {
    uint8_t *beg_ptr = (uint8_t*)MemToShadow(beg);
    uint8_t *end_ptr = (uint8_t*)MemToShadow(end);
    for (; beg_ptr < end_ptr; beg_ptr++)
      *beg_ptr = poison;
  }

  void CompactPoison(uint64_t poison_left,
                     uint64_t poison_main, uint64_t poison_right) {
    CompactPoisonRegion(rz1_beg(), rz1_end(), poison_left);
    CompactPoisonRegion(rz2_beg(), rz2_end(), poison_right);
    CompactPoisonRegion(    beg(),     end(), poison_main);
    if ((size % 8) && poison_right != 0 && poison_main == 0) {
      // one of the shadow bytes should be half-poisoned.
      uintptr_t last_qword = end();
      size_t addressible_bytes = size % 8;
      CHECK(addressible_bytes == (last_qword % 8));
      CHECK(addressible_bytes > 0 && addressible_bytes < 8);
      uint8_t *last_shadow = (uint8_t*)MemToShadow(last_qword);
      *last_shadow = addressible_bytes;
    }
  }

  __attribute__((noinline))
  void PoisonOnMalloc() {
    if (!F_poison_shadow) return;
    if (ASAN_IN_MEMORY_POISON) {
      uintptr_t beg1 = rz1_beg() + ReservedWords() * kWordSize;
      uintptr_t end1 = rz1_end();
      uintptr_t beg2 = rz2_beg();
      uintptr_t end2 = rz2_end();
      memset((char*)beg1, kInMemoryPoison8, end1 - beg1);
      memset((char*)beg2, kInMemoryPoison8, end2 - beg2);
      // TODO(kcc): inline memset
      return;
    }
    uintptr_t red_zone_words = F_red_zone_words;
    uintptr_t size_in_words = this->size_in_words();
#if !ASAN_BYTE_TO_BYTE_SHADOW
      // this->PrintOneLine("malloc poison: ", "\n");
      uint8_t *shadow = (uint8_t*)MemToShadow(rz1_beg());
      // Printf("shadow: %p\n", shadow);
      CompactPoison(0xa0a1a2a3a4a5a6a7ULL, 0,
                    0xb0b1b2b3b4b5b6b7ULL);
#else
    CHECK(AddrIsInMem((uintptr_t)rz1_beg()));
    CHECK(__WORDSIZE == 64);
    uintptr_t *shadow = (uintptr_t*)MemToShadow(rz1_beg());
    CHECK(AddrIsInShadow((uintptr_t)shadow));
    uintptr_t *x = shadow;
    for (; x < shadow + red_zone_words; x++) {
      *x = kPoisonedWordLeftRedZone;
    }
    CHECK(x == shadow + red_zone_words);
    for (; x < shadow + red_zone_words + size_in_words; x++) {
      *x = 0;
    }
    CHECK(x == shadow + red_zone_words + size_in_words);
    for (; x < shadow + real_size_in_words(); x++) {
      *x = kPoisonedWordRightRedZone;
    }
    char *ch_beg = (char*)(shadow + red_zone_words) + size;
    char *ch_end = (char*)(shadow + red_zone_words) + size_in_words * kWordSize;
    for (char *c = ch_beg; c < ch_end; c++) {
      *c = kPoisonedByte + (c - ch_beg);
    }
#endif
  }


  __attribute__((noinline))
  void PoisonOnFree(uintptr_t poison) {
    if (!F_poison_shadow) return;
    if (ASAN_IN_MEMORY_POISON) {
      if (poison) {
        memset((char*)beg(), kInMemoryPoison8, size);
      } else {
        uintptr_t beg1 = rz1_beg() + ReservedWords() * kWordSize;
        uintptr_t end1 = rz2_end();
        memset((char*)beg1, 0, end1 - beg1);
      }
      // TODO(kcc): inline memset
      return;
    }
    uintptr_t real_size_in_words = this->real_size_in_words();
    uintptr_t size_in_words = this->size_in_words();
    CHECK(AddrIsInMem(rz1_beg()));
#if !ASAN_BYTE_TO_BYTE_SHADOW
    if (poison) {
      CompactPoison(0xc0c1c2c3c4c5c6c7ULL,
                    0xd0d1d2d3d4d5d6d7ULL,
                    0xe0e1e2e3e4e5e6e7ULL);
    } else {
      uint8_t *beg = (uint8_t*)MemToShadow(rz1_beg());
      uint8_t *end = (uint8_t*)MemToShadow(rz2_end());
      memset(beg, 0, end - beg);
    }
#else
    CHECK(__WORDSIZE == 64);
    uintptr_t *shadow = (uintptr_t*)MemToShadow(rz1_beg());
    uintptr_t *x = shadow;
    for (x = shadow; x < shadow + real_size_in_words; x++) {
      *x = poison ? kPoisonedWordOnFree : 0;
    }
#endif
  }

  void CopyStackTrace(StackTrace &stack, uintptr_t *dest, size_t max_size) {
    size_t i;
    for (i = 0; i < std::min(max_size, stack.size); i++)
      dest[i] = stack.trace[i];
    if (i < max_size)
      dest[i] = 0;
  }

  uintptr_t *MallocStack() { return  (uintptr_t*)beg() + size_in_words(); }
  size_t MallocStackSize() {
    CHECK(F_malloc_context_size <= F_red_zone_words);
    return F_malloc_context_size;
  }
  uintptr_t *FreeStack()    { return (uintptr_t*)rz1_beg() + ReservedWords(); }
  size_t FreeStackSize()   {
    size_t available = size_in_words() + F_red_zone_words - ReservedWords();
    return std::min(available, F_malloc_context_size);
  }

  void CopyStackTraceForMalloc(StackTrace &stack) {
    CopyStackTrace(stack, MallocStack(), MallocStackSize());
  }

  void CopyStackTraceForFree(StackTrace &stack) {
    CopyStackTrace(stack, FreeStack(), FreeStackSize());
  }

  void PrintMallocStack() {
    PrintStack(MallocStack(), MallocStackSize());
  }

  void PrintFreeStack() {
    PrintStack(FreeStack(), FreeStackSize());
  }

  static size_t size_in_words(size_t size) {
    return (size + kWordSize - 1) / kWordSize;
  }
  static size_t real_size_in_words(size_t size) {
    return size_in_words(size) + F_red_zone_words * 2;
  }
};

class MallocInfo {
 public:
  void Init(size_t max_size) {
    max_size_ = max_size;
    pthread_mutex_init(&mu_, 0);
  }

  void print_malloced(const char *where) {
    Printf("%s: malloced:\n", where);
    for (Ptr *i = malloced_items_; i; i = i->next)
      i->PrintOneLine("  ");
  }

  void print_freed(const char *where) {
    Ptr *i = freed_items_;
    Printf("%s: freed:\n", where);
    if (i) do {
      i->PrintOneLine("  ");
      i = i->next;
    } while (i != freed_items_);
  }

  void print_lists(const char *where) {
    ScopedLock lock(&mu_);
    Printf("%s: lists: %p %p\n", where, malloced_items_, freed_items_);
    print_malloced(where);
    print_freed(where);
  }

  void on_malloc(Ptr *p) {
    p->prev = 0;
    p->magic = Ptr::kMallocedMagic;
    p->malloc_thread = tl_current_thread->Ref();
    p->free_thread = 0;
    ScopedLock lock(&mu_);
    if (malloced_items_) {
      malloced_items_->prev = p;
    }
    p->next = malloced_items_;
    malloced_items_ = p;
  }

  void on_free(Ptr *p) {
    CHECK(max_size_ > 0);
    CHECK(p);
    size_t real_size_in_words = p->real_size_in_words();
    CHECK(p->magic == Ptr::kMallocedMagic);
    p->magic = Ptr::kFreedMagic;
    p->free_thread = tl_current_thread->Ref();

    ScopedLock lock(&mu_);
    // remove from malloced list.
    {
      if (p == malloced_items_) {
        malloced_items_ = p->next;
        if (malloced_items_)
          malloced_items_->prev = 0;
      } else {
        Ptr *prev = p->prev;
        Ptr *next = p->next;
        if (prev) prev->next = next;
        if (next) next->prev = prev;
      }
    }

    if (!freed_items_) {
      p->next = p->prev = p;
    } else {
      Ptr *prev = freed_items_->prev;
      Ptr *next = freed_items_;
      p->next = next;
      p->prev = prev;
      prev->next = p;
      next->prev = p;
    }
    freed_items_ = p;
    cur_size_ += real_size_in_words * kWordSize;;
    while (cur_size_ && (cur_size_ > max_size_)) {
      pop();
    }
  }

  Ptr *find_freed(uintptr_t p) {
    Ptr *i = freed_items_;
    if (!i) return 0;
    do {
      // Printf("MallocInfo::find %lx in [%lx,%lx)\n",
      //        p, (uintptr_t)i, (uintptr_t)i + i->size);
      if (i->InRange(p))
        return i;
      i = i->next;
    } while (i != freed_items_);
    return 0;
  }

  Ptr *find_malloced(uintptr_t p) {
    for (Ptr *i = malloced_items_; i; i = i->next) {
      if (i->InRange(p)) return i;
    }
    return 0;
  }

  bool IsKnownAddressSLOW(uintptr_t addr) {
    ScopedLock lock(&mu_);
    return find_malloced(addr) || find_freed(addr);
  }

  void DescribeAddress(uintptr_t addr, size_t access_size) {
    ScopedLock lock(&mu_);

    // Check if we have this memory region in delay queue.
    Ptr *freed = find_freed(addr);
    Ptr *malloced = find_malloced(addr);

    if (freed && malloced) {
      Printf("ACHTUNG! the address is listed as both freed and malloced\n");
    }

    if (!freed && !malloced) {
      // Check the stack.
      AsanThread *t = AsanThread::FindThreadByStackAddress(addr);
      if (t) {
        Printf("Address "PP" is %ld bytes below T%d's stack top\n",
               addr, t->stack_top() - addr, t->tid());
        t->Announce();
        return;
      }
      Printf("ACHTUNG! the address is listed as neither freed nor malloced\n");
    }

    if (freed) {
      freed->DescribeAddress(addr, access_size);
      Printf("freed by thread T%d here:\n",
             freed->free_thread->tid());
      freed->PrintFreeStack();
      Printf("previously allocated by thread T%d here:\n",
             freed->malloc_thread->tid());
      freed->PrintMallocStack();
      tl_current_thread->Announce();
      freed->free_thread->Announce();
      freed->malloc_thread->Announce();
      return;
    }

    if (malloced) {
      malloced->DescribeAddress(addr, access_size);
      // size_t kStackSize = 100;
      // uintptr_t stack[kStackSize];
      // size_t stack_size = get_stack_trace_of_malloced_addr(malloced, stack, kStackSize);
      Printf("allocated by thread T%d here:\n",
             malloced->malloc_thread->tid());
      malloced->PrintMallocStack();
      // PrintStack(stack, stack_size);
      tl_current_thread->Announce();
      malloced->malloc_thread->Announce();
      return;
    }
    Printf("Address 0x%lx is not malloc-ed or (recently) freed\n", addr);
  }


 private:
  void pop() {
    CHECK(freed_items_);
    CHECK(cur_size_ > 0);
    Ptr *p = freed_items_->prev;
    CHECK(p);
    // Printf("pop  : %p cur_size_ = %ld; size = %ld\n", p, cur_size_, p->size);
    Ptr *next = p->next;
    Ptr *prev = p->prev;
    CHECK(next && prev);
    if (next == p) {
      freed_items_ = NULL;
    } else {
      next->prev = prev;
      prev->next = next;
    }
    cur_size_ -= p->real_size_in_words() * kWordSize;
    if (F_v >= 2) Printf("MallocInfo::pop %p\n", p);
    p->magic = Ptr::kRealyFreedMagic;
    p->PoisonOnFree(0);
    stats.real_frees++;
    stats.really_freed += p->real_size_in_words() * kWordSize;
    real_free((void*)p->orig_libc_ptr());
  }

  size_t max_size_;
  size_t cur_size_;
  Ptr *freed_items_;
  Ptr *malloced_items_;
  pthread_mutex_t mu_;
};

static MallocInfo malloc_info;

Ptr *asan_memalign(size_t size, size_t alignment, StackTrace &stack) {
  asan_init();
  CHECK(asan_inited);
  CHECK(F_red_zone_words >= Ptr::ReservedWords());
  size_t real_size_in_words = Ptr::real_size_in_words(size);
  size_t real_size_with_alignment =
      real_size_in_words * kWordSize + alignment;

  if (size >= F_large_malloc) {
    Printf("User requested %lu bytes:\n", size);
    PrintStack(stack);
  }
  uintptr_t orig = (uintptr_t)real_malloc(real_size_with_alignment);

  if (orig == 0) {
    OutOfMemoryMessage("main memory", size);
    PrintStack(stack);
    ShowStatsAndAbort();
  }


  if ((!AddrIsInMem(orig) || !AddrIsInMem(orig + real_size_with_alignment)) && 
      F_poison_shadow) {
    Printf("==%d== AddressSanitizer failure: malloc returned ["PP", "PP")\n",
           getpid(), orig, orig + real_size_with_alignment);
    ShowStatsAndAbort();
  }

  uintptr_t orig_beg = orig + F_red_zone_words * kWordSize;
  uintptr_t beg = orig_beg;

  if (alignment && (beg % alignment) != 0) {
    CHECK((alignment & (alignment - 1)) == 0);
    CHECK(alignment >= kWordSize);
    uintptr_t mod = beg % alignment;
    CHECK(alignment > mod);
    beg += alignment - mod;
    CHECK((beg % alignment) == 0);
  }
  uintptr_t rz1_beg = beg - F_red_zone_words * kWordSize;

  Ptr *p = (Ptr*)rz1_beg;
  p->size = size;
  p->orig_libc_offset = (uint32_t)(rz1_beg - orig);
  CHECK(p->orig_libc_ptr() == orig);
  CHECK(p->rz1_beg() == rz1_beg);
  CHECK(p->beg() == beg);
  CHECK(p->rz2_end() <= orig + real_size_with_alignment);

  stats.malloced += real_size_with_alignment;
  stats.malloced_redzones += F_red_zone_words * 2 * kWordSize;
  stats.mallocs++;

  if (F_v >= 2)
    p->PrintOneLine("asan_malloc: ");

  p->CopyStackTraceForMalloc(stack);
  malloc_info.on_malloc(p);
  p->PoisonOnMalloc();
  return p;
}

static void check_ptr_on_free(Ptr *p, void *addr, StackTrace &stack) {
  CHECK(p->beg() == (uintptr_t)addr);
  if (p->magic != Ptr::kMallocedMagic) {
    if (p->magic == Ptr::kFreedMagic) {
      Printf("attempting double-free on %p:\n", addr);
      PrintStack(stack);
      malloc_info.DescribeAddress(p->beg(), 1);
      ShowStatsAndAbort();
    } else {
      Printf("attempting free on address which was not malloc()-ed: %p\n",
             addr);
      PrintStack(stack);
      malloc_info.DescribeAddress(p->beg(), 1);
      ShowStatsAndAbort();
    }
  }
}

void asan_free(void *addr, StackTrace &stack) {
  CHECK(asan_inited);
  if (!addr) return;
  Ptr *p = (Ptr*)((uintptr_t*)addr - F_red_zone_words);
  size_t real_size_in_words = p->real_size_in_words();

  check_ptr_on_free(p, addr, stack);

  if (F_v >= 2)
    p->PrintOneLine("asan_free:   ", "\n");

  p->PoisonOnFree(1);
  p->CopyStackTraceForFree(stack);
  malloc_info.on_free(p);

  stats.frees++;
  stats.freed += real_size_in_words * kWordSize;
  stats.freed_since_last_stats += real_size_in_words * kWordSize;


  if (F_stats && stats.freed_since_last_stats > (1 << F_stats)) {
    stats.freed_since_last_stats = 0;
    stats.PrintStats();
  }
}

__attribute__((noinline))
static void asan_clear_mem(uintptr_t *mem, size_t n_words) {
  for (size_t i = 0; i < n_words; i++)
    mem[i] = 0;
}

void *asan_calloc(size_t nmemb, size_t size, StackTrace &stack) {
  CHECK(asan_inited);
  Ptr *p = asan_memalign(nmemb * size, 0, stack);
  void *ptr = p->raw_ptr();
  asan_clear_mem((uintptr_t*)ptr, (nmemb * size + kWordSize - 1) / kWordSize);
  return ptr;
}

__attribute__((noinline))
static void asan_copy_mem(uintptr_t *dst, uintptr_t *src, size_t n_words) {
  for (size_t i = 0; i < n_words; i++) {
    dst[i] = src[i];
  }
}

void *asan_realloc(void *addr, size_t size, StackTrace &stack) {
  CHECK(asan_inited);
  if (!addr) {
    Ptr *p = asan_memalign(size, 0, stack);
    return p->raw_ptr();
  }
  Ptr *p = (Ptr*)((uintptr_t*)addr - F_red_zone_words);
  check_ptr_on_free(p, addr, stack);
  if (F_v >= 2)
    p->PrintOneLine("asan_realloc: ", "\n");
  size_t old_size = p->size;
  Ptr *new_p = asan_memalign(size, 0, stack);
  void *new_ptr = new_p->raw_ptr();
  size_t memcpy_size = std::min(size, old_size);
  // memcpy(new_ptr, addr, memcpy_size);
  asan_copy_mem((uintptr_t*)new_ptr, (uintptr_t*)addr,
                (memcpy_size + kWordSize - 1) / kWordSize);
  asan_free(addr, stack);
  stats.reallocs++;
  stats.realloced += memcpy_size;
  return new_ptr;
}

// -------------------------- Interceptors ------------------- {{{1

extern "C"
void *malloc(size_t size) {
  if (tl_need_real_malloc) {
    void *res = real_malloc(size);
    // Printf("real_malloc: "PP" %ld\n", res, size);
    return res;
  }
  GET_STACK_TRACE_HERE_FOR_MALLOC;
  Ptr *p = asan_memalign(size, 0, stack);
  return p->raw_ptr();
}

extern "C"
void free(void *ptr) {
  if (tl_need_real_malloc) {
    // Printf("real_free "PP"\n", ptr);
    real_free(ptr);
    return;
  };
  GET_STACK_TRACE_HERE_FOR_FREE(ptr);
  asan_free(ptr, stack);
}

extern "C"
void *calloc(size_t nmemb, size_t size) {
  if (tl_need_real_malloc) {
    void *mem = real_malloc(nmemb * size);
    memset(mem, 0, nmemb *size);
    // Printf("real_calloc: "PP" %ld*%ld\n", mem, nmemb, size);
    return mem;
  }
  GET_STACK_TRACE_HERE_FOR_MALLOC;
  if (!asan_inited) {
    // Hack: dlsym calls calloc before real_calloc is retrieved from dlsym.
    const int kCallocPoolSize = 1024;
    static uintptr_t calloc_memory_for_dlsym[kCallocPoolSize];
    static size_t allocated;
    size_t size_in_words = ((nmemb * size) + kWordSize - 1) / kWordSize;
    void *mem = (void*)&calloc_memory_for_dlsym[allocated];
    allocated += size_in_words;
    CHECK(allocated < kCallocPoolSize);
    return mem;
  }
  return asan_calloc(nmemb, size, stack);
}

extern "C"
void *realloc(void *ptr, size_t size) {
  if (tl_need_real_malloc) {
    void *res = real_realloc(ptr, size);
    // Printf("real_malloc: "PP" "PP" %ld\n", res, ptr, size);
    return res;
  }
  GET_STACK_TRACE_HERE_FOR_MALLOC;
  return asan_realloc(ptr, size, stack);
}

extern "C"
void *memalign(size_t boundary, size_t size) {
  GET_STACK_TRACE_HERE_FOR_MALLOC;
  CHECK(!tl_need_real_malloc);
  Ptr *p = asan_memalign(size, boundary, stack);
  return p->raw_ptr();
}

extern "C"
int posix_memalign(void **memptr, size_t alignment, size_t size) {
  GET_STACK_TRACE_HERE_FOR_MALLOC;
  CHECK(!tl_need_real_malloc);
  // Printf("posix_memalign: %lx %ld\n", alignment, size);
  Ptr *p = asan_memalign(size, alignment, stack);
  *memptr = p->raw_ptr();
  CHECK(((uintptr_t)*memptr % alignment) == 0);
  return 0;
}
extern "C"
void *valloc(size_t size) {
  CHECK(0);
}


#if 1
void *operator new(size_t size) {
  GET_STACK_TRACE_HERE_FOR_MALLOC;
  CHECK(!tl_need_real_malloc);
  Ptr *p = asan_memalign(size, 0, stack);
  return p->raw_ptr();
}

void *operator new [] (size_t size) {
  GET_STACK_TRACE_HERE_FOR_MALLOC;
  CHECK(!tl_need_real_malloc);
  Ptr *p = asan_memalign(size, 0, stack);
  return p->raw_ptr();
}

void operator delete(void *ptr) {
  GET_STACK_TRACE_HERE_FOR_FREE(ptr);
  CHECK(!tl_need_real_malloc);
  asan_free(ptr, stack);
}

void operator delete [](void *ptr) {
  GET_STACK_TRACE_HERE_FOR_FREE(ptr);
  CHECK(!tl_need_real_malloc);
  asan_free(ptr, stack);
}
#endif

extern "C" int pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                                void *(*start_routine) (void *), void *arg) {
  GET_STACK_TRACE_HERE(kStackTraceMax, /*fast_unwind*/false);
  AsanThread *t = (AsanThread*)real_malloc(sizeof(AsanThread));
  new (t) AsanThread(start_routine, arg, &stack);
  return real_pthread_create(thread, attr, asan_thread_start, t);
}

#if __WORDSIZE == 64
extern "C"
void* mmap(void *start, size_t length,
           int prot, int flags,
           int fd, off_t offset) {
  void *res = real_mmap(start, length, prot, flags, fd, offset);
  if (F_v >= 2) {
    Printf("==%d== AddressSanitizer: "
            "the program called mmap directly. res: [%p,%p) size=%ld (0x%lx)\n",
            getpid(), res, (char*)res + length, length, length);

    PrintCurrentStack();
  }
  return res;
}
#endif

extern "C"
sig_t signal(int signum, sig_t handler) {
  if (signum != SIGSEGV) {
    return real_signal(signum, handler);
  }
}

extern "C"
int sigaction(int signum, const struct sigaction *act,
                struct sigaction *oldact) {
  if (signum != SIGSEGV) {
    return real_sigaction(signum, act, oldact);
  }
  return 0;
}

// -------------------------- Run-time entry ------------------- {{{1
extern "C"
void asan_slow_path(uintptr_t addr, uintptr_t size_and_is_w) {
  uintptr_t addr_8_aligned = (addr >> 3) << 3;
  uint64_t *ptr_8_aligned = (uint64_t*)addr_8_aligned;
  uint64_t this_qword = ptr_8_aligned[0];
  uint64_t &left_qword = ptr_8_aligned[-1];
  uint64_t &right_qword = ptr_8_aligned[1];

  if (this_qword != kInMemoryPoison64) {
    // Only some of the bytes in this qword are poisoned.
    // All bytes in this qword starting from addr should be poisoned
    uint8_t *beg = (uint8_t*)addr;
    uint8_t *end = (uint8_t*)(addr_8_aligned + 8);
    CHECK(beg < end);
    for (uint8_t *p8 = beg; p8 < end; p8++) {
      if (*p8 != kInMemoryPoison8) return;
    }
    // and also the memory at the right should be poisoned.
    if (right_qword != kInMemoryPoison64) return;
  } else {
    // All the bytes in this qword are poisoned.
    // Either left or right qword should be poisoned too.
    if (left_qword != kInMemoryPoison64 && right_qword != kInMemoryPoison64)
      return;
  }

  if (!malloc_info.IsKnownAddressSLOW(addr)) return;

  size_t size = size_and_is_w & 15;
  bool is_w = size_and_is_w  & 16;
  Printf("AddressSanitizer: slow path "PP" "PP" %s of size %ld\n",
         addr, addr, is_w ? "WRITE" : "READ",  size);
  uint8_t *beg = (uint8_t*)(addr - 16);
  uint8_t *end = (uint8_t*)(addr + 16);
  for (uint8_t *p = beg; p <= end; p++) {
    uint32_t val = *p;
    if (p == (uint8_t*)addr) {
      Printf("-- %x -- ", val);
    } else {
      Printf("%x", val);
    }
  }
  Printf("\n");
  malloc_info.DescribeAddress(addr, size);
}

static void PrintUnwinderHint() {
  if (F_fast_unwind) {
    Printf("HINT: if your stack trace looks short or garbled, "
           "use ASAN_OPTIONS=fast_unwind=0\n");
  }
}

static void     OnSIGSEGV(int, siginfo_t *siginfo, void *context) {
  uintptr_t addr = (uintptr_t)siginfo->si_addr;
  // If we trapped while accessing an address that looks like shadow
  // -- just map that page.
  uintptr_t page = addr & ~(kPageSize - 1);
  if (AddrIsInShadow(addr)) {
    size_t start_page = page & ~(kPageClusterSize * kPageSize - 1);
    size_t end_page = start_page + kPageClusterSize * kPageSize;
    size_t cluster_index = start_page >> (kPageClusterSizeBits + kPageSizeBits);
    size_t cluster_word_idx = cluster_index / kWordSizeInBits;
    size_t cluster_bits_idx = cluster_index % kWordSizeInBits;
    size_t cluster_bits_mask = 1UL << cluster_bits_idx;
    CHECK(cluster_word_idx < sizeof(mapped_clusters));

    ScopedLock lock(&shadow_lock);
    if (mapped_clusters[cluster_word_idx] & cluster_bits_mask) {
      // already allocated
      return;
    }
    mapped_clusters[cluster_word_idx] |= cluster_bits_mask;

    if (F_v >= 2)
      Printf("==%d==mapping shadow: [0x%lx, 0x%lx); %ld pages\n",
             getpid(), start_page, end_page, kPageClusterSize);
    if(AddrIsInHighShadow(addr)) {
      mmap_high_shadow(start_page, kPageClusterSize);
    } else {
      CHECK(AddrIsInLowShadow(addr));
      mmap_low_shadow(start_page, kPageClusterSize);
    }
    return;
  }

  ucontext_t *ucontext = (ucontext_t*)context;
#ifdef __APPLE__
  uintptr_t pc = ucontext->uc_mcontext->__ss.__eip;
#else // assume linux
#if __WORDSIZE == 64
  uintptr_t pc = ucontext->uc_mcontext.gregs[REG_RIP];
#else
  uintptr_t pc = ucontext->uc_mcontext.gregs[REG_EIP];
#endif
#endif
  uintptr_t shadow_addr = BadToShadow(addr);
  uintptr_t real_addr = ShadowToMem(shadow_addr);
  uint8_t *insn = (uint8_t*)pc;
  int access_size_and_type = 0;
  // TODO(kcc): disassemble all variants.
  if (insn[0] == 0xc6 && insn[1] == 0x04 && insn[2] == 0xcd) {
    // c6 04 cd 00 00 00 00 12 movb   $0x12,0x0(,%ecx,8)
    access_size_and_type = insn[7];
  } else if (insn[0] == 0xc6 && insn[1] == 0x04) {
    // c6 04 1b 14             movb   $0x14,(%rbx,%rbx,1)
    access_size_and_type = insn[3];
  } else if (insn[0] == 0x43 && insn[1] == 0xc6 && insn[2] == 0x04) {
    // 43 c6 04 09 18          movb   $0x18,(%r9,%r9,1)
    access_size_and_type = insn[4];
  }
  bool is_write = access_size_and_type & 16;
  int access_size = access_size_and_type & 15;

  if (F_print_malloc_lists) {
    malloc_info.print_lists("OnSIGSEGV");
  }
  Printf("==================================================================\n");
  PrintUnwinderHint();
  proc_self_maps.Init();
  Printf("==%d== ERROR: AddressSanitizer crashed on address "PP" at pc 0x%lx\n",
         getpid(), addr, pc);

  if (!AddrIsInShadow(shadow_addr)) {
    Printf("The failing address is not inside the shadow region.\n"
           "AddressSanitizer can not provide additional info. ABORTING\n");
    PrintCurrentStack(pc);
    Printf("shadow: "PP"\n", shadow_addr);
    PrintBytes("PC: ",(uintptr_t*)pc);
    ShowStatsAndAbort();
  }

  uintptr_t real_addr_from_shadow = *(uintptr_t*)shadow_addr;
  if (F_debug) {
    Printf("ShadowToMem:    "PP"\n", real_addr);
    Printf("AddrFromShadow: "PP"\n", real_addr_from_shadow);
  }
  if (real_addr_from_shadow >= real_addr && real_addr_from_shadow < real_addr + 8) {
    real_addr = real_addr_from_shadow;
  }

  Printf("%s of size %d at "PP"; shadow: "PP"; mem: "PP" thread T%d\n",
          access_size ? (is_write ? "WRITE" : "READ") : "ACCESS",
          access_size,
          addr, shadow_addr, real_addr,
          tl_current_thread->tid());

  if (F_debug) {
    PrintBytes("PC: ",(uintptr_t*)pc);
  }

  PrintCurrentStack(pc);

  CHECK(AddrIsInMem(real_addr));
  CHECK(shadow_addr == MemToShadow(real_addr));

  malloc_info.DescribeAddress(real_addr, access_size);

  if (F_print_maps) {
    proc_self_maps.Print();
  }

  if (F_abort_after_first) {
    Printf("==%d== ABORTING\n", getpid()),
    stats.PrintStats();
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
    AsanAbort();
  } else {
    mmap_pages(page, 1, "bad memory");
  }
}

// -------------------------- Init ------------------- {{{1
static int64_t IntFlagValue(const char *flags, const char *flag,
                            int64_t default_val) {
  if (!flags) return default_val;
  const char *str = strstr(flags, flag);
  if (!str) return default_val;
  return atoll(str + strlen(flag));
}

static void asan_atexit() {
  Printf("AddressSanitizer exit stats:\n");
  stats.PrintStats();
}

static void asan_init() {
  if (asan_inited) return;
  asan_out = stderr;

  // flags
  const char *options = getenv("ASAN_OPTIONS");
  F_malloc_context_size =
      IntFlagValue(options, "malloc_context_size=", kMallocContextSize);
  CHECK(F_malloc_context_size <= kMallocContextSize);

  F_v = IntFlagValue(options, "v=", 0);
  CHECK(Ptr::ReservedWords() <= 8);

  F_red_zone_words = IntFlagValue(options, "red_zone_words=", 16);
  if (F_red_zone_words & 7) {
    F_red_zone_words = (F_red_zone_words + 7) & ~7;
  }
  CHECK(F_red_zone_words >= 8 && (F_red_zone_words % 8) == 0);

  F_print_maps     = IntFlagValue(options, "print_maps=", 0);
  F_print_malloc_lists = IntFlagValue(options, "print_malloc_lists=", 0);
  F_abort_after_first = IntFlagValue(options, "abort_after_first=", 1);
  F_atexit = IntFlagValue(options, "atexit=", 0);
  F_poison_shadow = IntFlagValue(options, "poison_shadow=", 1);
  F_large_malloc = IntFlagValue(options, "large_malloc=", 1 << 30);
  F_stats = IntFlagValue(options, "stats=", 0);
  F_symbolize = IntFlagValue(options, "symbolize=", 1);
  F_demangle = IntFlagValue(options, "demangle=", 1);
  F_debug = IntFlagValue(options, "debug=", 0);
  F_fast_unwind = IntFlagValue(options, "fast_unwind=", 1);

  if (F_atexit) {
    atexit(asan_atexit);
  }

  size_t F_delay_queue_size =
      IntFlagValue(options, "delay_queue_size=", 1UL << 28);
  malloc_info.Init(F_delay_queue_size);

  if (F_malloc_context_size > F_red_zone_words)
    F_malloc_context_size = F_red_zone_words;

  CHECK((real_sigaction = (sigaction_f)dlsym(RTLD_NEXT, "sigaction")));
  CHECK((real_signal = (signal_f)dlsym(RTLD_NEXT, "signal")));
  CHECK((real_mmap = (mmap_f)dlsym(RTLD_NEXT, "mmap")));
  CHECK((real_malloc = (malloc_f)dlsym(RTLD_NEXT, "malloc")));
  CHECK((real_realloc = (realloc_f)dlsym(RTLD_NEXT, "realloc")));
  CHECK((real_free = (free_f)dlsym(RTLD_NEXT, "free")));
  CHECK((real_pthread_create = (pthread_create_f)dlsym(RTLD_NEXT, "pthread_create")));


  // Set the SEGV handler.
  {
    struct sigaction sigact;
    memset(&sigact, 0, sizeof(sigact));
    sigact.sa_sigaction = OnSIGSEGV;
    sigact.sa_flags = SA_SIGINFO;
    real_sigaction(SIGSEGV, &sigact, 0);
  }

  pthread_mutex_init(&shadow_lock, 0);

  proc_self_maps.Init();

  if (__WORDSIZE == 32) {
    // Map the entire shadow region.
    uintptr_t beg = kCROSShadowMask32;
    uintptr_t end = kCROSShadowMask32 << 1;
    mmap_pages(beg, (end - beg) / kPageSize, "32-bit shadow memmory");
  }


  AsanThread *t = (AsanThread*)real_malloc(sizeof(AsanThread));
  new (t) AsanThread(0, 0, 0);
  tl_current_thread = t;
  tl_current_thread->ThreadStart();

  asan_inited = 1;

  const char *asan_filter = getenv("ASAN_FILTER");
  if (asan_filter) {
    FILE *p = popen(asan_filter, "w");
    if (p)
      asan_out = p;
  }


  if (F_v) {
    Printf("==%d== AddressSanitizer Init done ***\n", getpid());
    Printf("LowMem     : ["PP","PP")\n", 0, kLowMemEnd);
    Printf("LowShadow  : ["PP","PP")\n", kLowShadowBeg, kLowShadowEnd);
    Printf("HighShadow : ["PP","PP")\n", kHighShadowBeg, kHighShadowEnd);
    Printf("HighMem    : ["PP","PP")\n", kHighMemBeg, kHighMemEnd);
    Printf("red_zone_words=%ld\n", F_red_zone_words);
    Printf("malloc_context_size=%ld\n", (int)F_malloc_context_size);
    Printf("fast_unwind=%d\n", (int)F_fast_unwind);
  }
}
