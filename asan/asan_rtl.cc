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

#include "asan_int.h"
#include "asan_rtl.h"
#include "asan_lock.h"

#include "sysinfo.h"

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
// must not include <setjmp.h>

using std::string;

#include "unwind.h"

#include "bfd_symbolizer/bfd_symbolizer.h"

static void PrintCurrentStack(uintptr_t pc = 0);
static void ShowStatsAndAbort();



#define UNIMPLEMENTED() CHECK("unimplemented" && 0)

__attribute__((constructor)) static void asan_init();

#ifndef __APPLE__
static __thread bool tl_need_real_malloc;
#else
static const bool tl_need_real_malloc = false;
#endif

// -------------------------- Flags ------------------------- {{{1
static const size_t kStackTraceMax = 64;
static const size_t kMallocContextSize = 30;
static int    F_v;
static size_t F_malloc_context_size = kMallocContextSize;
static size_t F_red_zone_words;  // multiple of 8
static size_t F_delay_queue_size;
static int    F_print_maps;
static int    F_print_malloc_lists;
static int    F_atexit;
static uintptr_t F_large_malloc;
static bool   F_poison_shadow;
static int    F_stats;
static int    F_debug;
static int    F_symbolize;  // use in-process symbolizer
static int    F_demangle;
static bool   F_fast_unwind;
static uintptr_t  F_debug_malloc_size;
static bool   F_mt;  // set to 0 if you have only one thread.

#if __WORDSIZE == 32
static const int F_protect_shadow = 1;
#else
static int F_protect_shadow;
#endif



// -------------------------- Atomic ---------------- {{{1
int AtomicInc(int *a) {
  if (!F_mt) return ++(*a);
  return __sync_add_and_fetch(a, 1);
}

int AtomicDec(int *a) {
  if (!F_mt) return --(*a);
  return __sync_add_and_fetch(a, -1);
}

// -------------------------- Printf ---------------- {{{1
static FILE *asan_out;

void __asan_printf(const char *format, ...) {
  const int kLen = 1024 * 4;
  char buffer[kLen];
  va_list args;
#ifndef __APPLE__
  tl_need_real_malloc = true;  // TODO(kcc): make sure we don't malloc here.
#endif
  va_start(args, format);
  vsnprintf(buffer, kLen, format, args);
  fwrite(buffer, 1, strlen(buffer), asan_out);
  fflush(asan_out);
  va_end(args);
#ifndef __APPLE__
  tl_need_real_malloc = false;
#endif
}


// -------------------------- Globals --------------------- {{{1
static int asan_inited;
size_t __asan_quarantine_size;

#if __WORDSIZE == 64
static uintptr_t
  mapped_clusters[(1UL << kPossiblePageClustersBits) / kWordSizeInBits];
static AsanLock shadow_lock;
#endif

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
typedef void (*longjmp_f)(void *env, int val);
typedef void (*cxa_throw_f)(void *, void *, void *);
typedef int (*pthread_create_f)(pthread_t *thread, const pthread_attr_t *attr,
                              void *(*start_routine) (void *), void *arg);

static sigaction_f      real_sigaction;
static signal_f         real_signal;
static mmap_f           real_mmap;
#ifndef __APPLE__
static malloc_f         real_malloc;
static realloc_f        real_realloc;
static free_f           real_free;
#endif  // __APPLE__
static longjmp_f        real_longjmp;
static longjmp_f        real_siglongjmp;
static cxa_throw_f      real_cxa_throw;
static pthread_create_f real_pthread_create;

#ifdef __APPLE__
#include <malloc/malloc.h>

static malloc_zone_t *system_malloc_zone = NULL;

void *real_malloc(size_t size) {
  CHECK(system_malloc_zone);
  return malloc_zone_malloc(system_malloc_zone, size);
}

void real_free(void *ptr) {
  CHECK(system_malloc_zone);
  return malloc_zone_free(system_malloc_zone, ptr);
}

void *real_realloc(void *ptr, size_t size) {
  CHECK(system_malloc_zone);
  return malloc_zone_realloc(system_malloc_zone, ptr, size);
}

#endif  // __APPLE__

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
#if __WORDSIZE == 64
    Printf("Stats: %ldM of shadow memory allocated in %ld clusters\n"
           "             (%ldM each, %ld low and %ld high)\n",
           ((low_shadow_maps + high_shadow_maps) * kPageClusterSize * kPageSize)>>20,
           low_shadow_maps + high_shadow_maps,
           (kPageClusterSize * kPageSize) >> 20,
           low_shadow_maps, high_shadow_maps);
#endif
  }
};

static Stats stats;

// -------------------------- Misc ---------------- {{{1
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

// -------------------------- Mapping ---------------- {{{1
static bool AddrIsInLowMem(uintptr_t a) {
  return a < kLowMemEnd;
}

static bool AddrIsInLowShadow(uintptr_t a) {
  return a >= kLowShadowBeg && a <= kLowShadowEnd;
}

static bool AddrIsInHighMem(uintptr_t a) {
  return a >= kHighMemBeg && a <= kHighMemEnd;
}

static bool AddrIsInMem(uintptr_t a) {
  return AddrIsInLowMem(a) || AddrIsInHighMem(a);
}

static uintptr_t MemToShadow(uintptr_t p) {
  CHECK(AddrIsInMem(p));
  return MEM_TO_SHADOW(p);
}

static bool AddrIsInHighShadow(uintptr_t a) {
  return a >= kHighShadowBeg && a <=  kHighMemEnd;
}

static bool AddrIsInShadow(uintptr_t a) {
  return AddrIsInLowShadow(a) || AddrIsInHighShadow(a);
}

// ----------------------- ProcSelfMaps ----------------------------- {{{1
class ProcSelfMaps {
 public:
  void Init() {
    ProcMapsIterator it(0, &proc_self_maps_);   // 0 means "current pid"

    uint64 start, end, offset;
    int64 inode;
    char *flags, *filename;
    map_size_ = 0;
    while (it.Next(&start, &end, &flags, &offset, &inode, &filename)) {
      CHECK(map_size_ < kMaxProcSelfMapsSize);
      Mapping &mapping = memory_map[map_size_];
      mapping.beg = start;
      mapping.end = end;
      mapping.name_beg = filename;
      map_size_++;
    }
  }

  void Print() {
    Printf("%s\n", proc_self_maps_);
  }

  void FilterOutAsanRtlFileName(char file_name[]) {
    if (strstr(file_name, "asan_rtl.cc")) {
      strcpy(file_name,   "_asan_rtl_");
    }
  }

  void PrintPc(uintptr_t pc, int idx) {
    const int kLen = 1024;
#ifndef __APPLE__
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
        FilterOutAsanRtlFileName(file);
        Printf("    #%d 0x%lx in %s %s:%d\n", idx, pc, func, file, line);
        return;
      }
      // bfd failed
    }
#endif

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
  ProcMapsIterator::Buffer proc_self_maps_;
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
    // int line;
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

  AsanThread(AsanThread *parent, void *(*start_routine) (void *),
             void *arg, StackTrace *stack)
    : parent_(parent),
      start_routine_(start_routine),
      arg_(arg),
      announced_(false),
      tid_(AtomicInc(&n_threads_) - 1),
      refcount_(1) {
    if (stack) {
      stack_ = *stack;
    }
    if (tid_ == 0) {
      live_threads_ = next_ = prev_ = this;
    }
  }

  void SetThreadStackTopAndBottom() {
#ifdef __APPLE__
   size_t stacksize = pthread_get_stacksize_np(pthread_self());
   void *stackaddr = pthread_get_stackaddr_np(pthread_self());
   stack_top_ = (uintptr_t)stackaddr;
   stack_bottom_ = stack_top_ - stacksize;
   int local;
   CHECK(AddrIsInStack((uintptr_t)&local));
#else
    tl_need_real_malloc = true;
    pthread_attr_t attr;
    CHECK (pthread_getattr_np(pthread_self(), &attr) == 0);
    size_t stacksize = 0;
    void *stackaddr = NULL;
    pthread_attr_getstack(&attr, &stackaddr, &stacksize);
    pthread_attr_destroy(&attr);
    tl_need_real_malloc = false;

    const int kMaxStackSize = 16 * (1 << 20);  // 16M
    stack_top_ = (uintptr_t)stackaddr + stacksize;
    stack_bottom_ = (uintptr_t)stackaddr;
    // When running under the GNU make command, pthread_attr_getstack
    // returns garbage for a stacksize.
    if (stacksize > kMaxStackSize) {
      Printf("WARNING: pthread_attr_getstack returned "PP" as stacksize\n",
             stacksize);
      stack_bottom_ = stack_top_ - kMaxStackSize;
    }
    CHECK(AddrIsInStack((uintptr_t)&attr));
#endif
  }

  void *ThreadStart() {
    SetThreadStackTopAndBottom();
    if (F_v == 1) {
      int local = 0;
      Printf ("T%d: stack ["PP","PP") size 0x%lx; local="PP"\n",
              tid_, stack_bottom_, stack_top_, stack_top_ - stack_bottom_, &local);
    }
    CHECK(AddrIsInMem(stack_bottom_));
    CHECK(AddrIsInMem(stack_top_));

    // clear the shadow state for the entire stack.
    uintptr_t shadow_bot = MemToShadow(stack_bottom_);
    uintptr_t shadow_top = MemToShadow(stack_top_);
    memset((void*)shadow_bot, 0, shadow_top - shadow_bot);

    { // Insert this thread into live_threads_
      ScopedLock lock(&mu_);
      this->next_ = live_threads_;
      this->prev_ = live_threads_->prev_;
      this->prev_->next_ = this;
      this->next_->prev_ = this;
    }

    if (!start_routine_) return 0;

    void *res = start_routine_(arg_);

    if (F_v == 1) {
      Printf("T%d exited\n", tid_);
    }

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
      CHECK(parent_);
      Printf("Thread T%d created by T%d here:\n", tid_, parent_->tid_);
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
  AsanThread *parent_;
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
  static AsanLock mu_;
};

int AsanThread::n_threads_;
AsanThread *AsanThread::live_threads_;
AsanLock AsanThread::mu_;
#ifndef __APPLE__
static __thread AsanThread *tl_current_thread;
#else
static pthread_key_t g_tls_key;
static AsanThread *g_thread_0 = NULL;
// This flag is updated only once at program startup, and then read
// by concurrent threads.
static bool tls_key_created = false;
#endif

static AsanThread* GetCurrentThread() {
#ifdef __APPLE__
  CHECK(tls_key_created);
  AsanThread *thread = (AsanThread*)pthread_getspecific(g_tls_key);
  // After the thread calls _pthread_exit() the TSD is unavailable
  // and pthread_getspecific() may return NULL. Thus we associate the further
  // allocations (originating from the guts of libpthread) with thread 0.
  if (thread) {
    return thread;
  } else {
    return g_thread_0;
  }
#else
  return tl_current_thread;
#endif
}
static void SetCurrentThread(AsanThread *t) {
#ifdef __APPLE__
  CHECK(0 == pthread_setspecific(g_tls_key, t));
  CHECK(pthread_getspecific(g_tls_key));
#else
  tl_current_thread = t;
#endif
}

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
  AsanThread *t = GetCurrentThread();
  if (!t) return;
  uintptr_t *prev_frame = frame;
  uintptr_t *top = (uintptr_t*)t->stack_top();
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

// given sp and bp, find the frame to which addr belongs.
static int TryToFindFrameForStackAddress(uintptr_t sp, uintptr_t bp,
                                         uintptr_t addr) {
  if (bp == 0 || sp == 0)  return -1;
  AsanThread *t = GetCurrentThread();
  if (!t->AddrIsInStack(bp)) return -1;
  if (!t->AddrIsInStack(sp)) return -1;
  if (addr < sp) return -1; // Probably, should nto happen.
  if (addr < bp) return 0;  // current frame.
  uintptr_t *top = (uintptr_t*)t->stack_top();
  uintptr_t *frame = (uintptr_t*)bp;
  uintptr_t *prev_frame = frame;
  int res = 0;
  while (frame >= prev_frame && frame < top && frame < (uintptr_t*)addr) {
    // Printf("%d ZZZ "PP" addr-frame="PP" \n", res, frame, addr-(uintptr_t)frame);
    CHECK(t->AddrIsInStack((uintptr_t)frame));
    prev_frame = frame;
    frame = (uintptr_t*)frame[0];
    res++;
  }
  return res;
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
  AsanThread *t= (AsanThread*)arg;
  SetCurrentThread(t);
  return t->ThreadStart();
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

static char *mmap_pages(size_t start_page, size_t n_pages, const char *mem_type,
                        bool abort_on_failure = true) {
  void *res = real_mmap((void*)start_page, kPageSize * n_pages,
                   PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANON | MAP_FIXED, 0, 0);
  // Printf("%p => %p\n", (void*)start_page, res);
  char *ch = (char*)res;
  if (res == (void*)-1L && abort_on_failure) {
    OutOfMemoryMessage(mem_type, n_pages * kPageSize);
    ShowStatsAndAbort();
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
  void *res = real_mmap((void*)beg, end - beg + 1,
                   PROT_NONE,
                   MAP_PRIVATE | MAP_ANON | MAP_FIXED, 0, 0);
  CHECK(res == (void*)beg);
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

// We create right redzones for globals and keep the gobals in a linked list.
struct Global {
  Global *next;   // Next in the list.
  uintptr_t beg;  // Address of the global.
  size_t size;    // Size of the global.

  void PoisonRedZones() {
    uintptr_t shadow = MemToShadow(beg);
    // full right redzone
    uintptr_t right_rz2_offset = 4 * ((size + kAsanRedzone - 1)
                                     / kAsanRedzone);
    *(uint32_t*)(shadow + right_rz2_offset) = 0xcacacaca;
    if ((size % kAsanRedzone) != 0) {
      // partial right redzone
      uint64_t right_rz1_offset = 4 * (size / kAsanRedzone);
      CHECK(right_rz1_offset == right_rz2_offset - 4);
      *(uint32_t*)(shadow + right_rz1_offset) =
          kPartialRedzonePoisonValues[size % kAsanRedzone];
    }
  }

  size_t GetAlignedSize() {
    return ((size + kAsanRedzone - 1) / kAsanRedzone) * kAsanRedzone;
  }

  bool DescribeAddrIfMyRedZone(uintptr_t addr) {
    if (addr < beg - kAsanRedzone) return false;
    if (addr >= beg + GetAlignedSize() + kAsanRedzone) return false;
    Printf(""PP" is located ", addr);
    if (addr < beg) {
      Printf("%d bytes to the left", beg - addr) ;
    } else if (addr >= beg + size) {
      Printf("%d bytes to the right", addr - (beg + size));
    } else {
      Printf("%d bytes inside", addr - beg);  // Can it happen?
    }
    Printf(" of global variable "PP"\n", beg + kAsanRedzone);
    return true;
  }
};

static Global *g_globals_list;

static bool DescribeAddrIfGlobal(uintptr_t addr) {
  bool res = false;
  for (Global *g = g_globals_list; g; g = g->next) {
    res |= g->DescribeAddrIfMyRedZone(addr);
  }
  return res;
}

// exported function
extern "C" void __asan_register_global(uintptr_t addr, size_t size) {
  asan_init();
  CHECK(AddrIsInMem(addr));
  uintptr_t shadow = MemToShadow(addr);
  //Printf("global: "PP" "PP" %ld \n", addr, shadow, size);
  uintptr_t aligned_size =
      ((size + kAsanRedzone - 1) / kAsanRedzone) * kAsanRedzone;
  Global *g = (Global*)(addr + aligned_size);
  g->next = g_globals_list;
  g->size = size;
  g->beg = addr;
  g_globals_list = g;
  g->PoisonRedZones();
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

  void PrintRaw(int where) {
    Printf("this=%p magic=%x orig_libc_offset=%x size=%lx "
           "next=%p prev=%p mt=%p ft=%p where=%d\n",
           this, magic, orig_libc_offset, size,
           next, prev, malloc_thread, free_thread, where);
  }

  void DescribeAddress(uintptr_t addr, size_t access_size) {
    CHECK(InRange(addr));
    Printf(""PP" is located ", addr);
    if (InRz1(addr)) {
      Printf("%ld bytes to the left of", rz1_end() - addr);
    } else if (InRz2(addr) || InRz2(addr + access_size - 1)) {
      uintptr_t offset = addr - rz2_beg();
      if (addr < rz2_beg()) {
        CHECK(addr + access_size > rz2_beg());
        offset = 0;
      }
      Printf("%ld bytes to the right of", offset);
    } else {
      CHECK(InAllocated(addr));
      Printf("%ld bytes inside of", addr - beg());
    }
    Printf(" %ld-byte region ["PP","PP")\n" , size, beg(), end());
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
    uintptr_t red_zone_words = F_red_zone_words;
    uintptr_t size_in_words = this->size_in_words();
    // this->PrintOneLine("malloc poison: ", "\n");
    uint8_t *shadow = (uint8_t*)MemToShadow(rz1_beg());
    // Printf("shadow: %p\n", shadow);
    CompactPoison(0xa0a1a2a3a4a5a6a7ULL, 0,
                  0xb0b1b2b3b4b5b6b7ULL);
  }


  __attribute__((noinline))
  void PoisonOnFree(uintptr_t poison) {
    if (!F_poison_shadow) return;
    uintptr_t real_size_in_words = this->real_size_in_words();
    uintptr_t size_in_words = this->size_in_words();
    CHECK(AddrIsInMem(rz1_beg()));
    if (poison) {
      CompactPoison(0xc0c1c2c3c4c5c6c7ULL,
                    0xd0d1d2d3d4d5d6d7ULL,
                    0xe0e1e2e3e4e5e6e7ULL);
    } else {
      uint8_t *beg = (uint8_t*)MemToShadow(rz1_beg());
      uint8_t *end = (uint8_t*)MemToShadow(rz2_end());
      memset(beg, 0, end - beg);
    }
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
    p->malloc_thread = GetCurrentThread()->Ref();
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
    p->free_thread = GetCurrentThread()->Ref();

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

  void DescribeAddress(uintptr_t sp, uintptr_t bp, uintptr_t addr, size_t access_size) {
    ScopedLock lock(&mu_);

    // Check if this is a global.
    if (DescribeAddrIfGlobal(addr))
      return;

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
        Printf("Address "PP" is %ld bytes below T%d's stack top",
               addr, t->stack_top() - addr, t->tid());
        int frame = TryToFindFrameForStackAddress(sp, bp, addr);
        if (frame >= 0) {
          Printf(" (allocated in frame #%d)\n", frame);
        } else {
          Printf("\n");
        }
        Printf("HINT: this may be a false positive if your program uses "
               "some custom stack unwind mechanism\n"
               "      (longjmp and C++ exceptions *are* supported)\n");
        t->Announce();
        return;
      }
      Printf("ACHTUNG! the address is listed as neither freed nor malloced\n");
    }

    if (freed) {
      if (F_v) freed->PrintRaw(__LINE__);
      freed->DescribeAddress(addr, access_size);
      Printf("freed by thread T%d here:\n",
             freed->free_thread->tid());
      freed->PrintFreeStack();
      Printf("previously allocated by thread T%d here:\n",
             freed->malloc_thread->tid());
      freed->PrintMallocStack();
      GetCurrentThread()->Announce();
      freed->free_thread->Announce();
      freed->malloc_thread->Announce();
      return;
    }

    if (malloced) {
      if (F_v) malloced->PrintRaw(__LINE__);
      malloced->DescribeAddress(addr, access_size);
      // size_t kStackSize = 100;
      // uintptr_t stack[kStackSize];
      // size_t stack_size = get_stack_trace_of_malloced_addr(malloced, stack, kStackSize);
      Printf("allocated by thread T%d here:\n",
             malloced->malloc_thread->tid());
      malloced->PrintMallocStack();
      // PrintStack(stack, stack_size);
      GetCurrentThread()->Announce();
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
  AsanLock mu_;
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

  if (F_debug_malloc_size && (F_debug_malloc_size == p->size)) {
    p->PrintOneLine("asan_malloc: ");
    p->PrintRaw(__LINE__);
    PrintCurrentStack();
    stats.PrintStats();
  }

  p->CopyStackTraceForMalloc(stack);
  malloc_info.on_malloc(p);
  p->PoisonOnMalloc();
  return p;
}

__attribute__((noinline))
static void check_ptr_on_free(Ptr *p, void *addr, StackTrace &stack) {
  CHECK(p->beg() == (uintptr_t)addr);
  if (p->magic != Ptr::kMallocedMagic) {
    if (p->magic == Ptr::kFreedMagic) {
      Printf("attempting double-free on %p:\n", addr);
      PrintStack(stack);
      malloc_info.DescribeAddress(0, 0, p->beg(), 1);
      ShowStatsAndAbort();
    } else {
      Printf("attempting free on address which was not malloc()-ed: %p\n",
             addr);
      PrintStack(stack);
      malloc_info.DescribeAddress(0, 0, p->beg(), 1);
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

  if (F_debug_malloc_size && (F_debug_malloc_size == p->size)) {
    p->PrintOneLine("asan_free:   ");
    p->PrintRaw(__LINE__);
    PrintCurrentStack();
    stats.PrintStats();
  }

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
  return NULL;
}


#if 1
#define OPERATOR_NEW_BODY \
  GET_STACK_TRACE_HERE_FOR_MALLOC;\
  CHECK(!tl_need_real_malloc);\
  Ptr *p = asan_memalign(size, 0, stack);\
  return p->raw_ptr();

void *operator new(size_t size) { OPERATOR_NEW_BODY; }
void *operator new[](size_t size) { OPERATOR_NEW_BODY; }
void *operator new(size_t size, std::nothrow_t const&) { OPERATOR_NEW_BODY; }
void *operator new[](size_t size, std::nothrow_t const&) { OPERATOR_NEW_BODY; }

#define OPERATOR_DELETE_BODY \
  GET_STACK_TRACE_HERE_FOR_FREE(ptr);\
  CHECK(!tl_need_real_malloc);\
  asan_free(ptr, stack);

void operator delete(void *ptr) { OPERATOR_DELETE_BODY; }
void operator delete[](void *ptr) { OPERATOR_DELETE_BODY; }
void operator delete(void *ptr, std::nothrow_t const&) { OPERATOR_DELETE_BODY; }
void operator delete[](void *ptr, std::nothrow_t const&) { OPERATOR_DELETE_BODY; }
#endif

extern "C" int pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                                void *(*start_routine) (void *), void *arg) {
  GET_STACK_TRACE_HERE(kStackTraceMax, /*fast_unwind*/false);
  AsanThread *t = (AsanThread*)real_malloc(sizeof(AsanThread));
  new (t) AsanThread(GetCurrentThread(), start_routine, arg, &stack);
  return real_pthread_create(thread, attr, asan_thread_start, t);
}

#if 0
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
#ifdef __APPLE__
  if (signum != SIGSEGV && signum != SIGBUS && signum != SIGILL) {
#else
  if (signum != SIGSEGV && signum != SIGILL) {
#endif
    return real_signal(signum, handler);
  }
}

extern "C"
int sigaction(int signum, const struct sigaction *act,
                struct sigaction *oldact) {
#ifdef __APPLE__
  if (signum != SIGSEGV && signum != SIGBUS && signum != SIGILL) {
#else
  if (signum != SIGSEGV && signum != SIGILL) {
#endif
    return real_sigaction(signum, act, oldact);
  }
  return 0;
}


static void UnpoisonStackFromHereToTop() {
  int local_stack;
  uintptr_t top = GetCurrentThread()->stack_top();
  uintptr_t bottom = ((uintptr_t)&local_stack - kPageSize) & ~(kPageSize-1);
  uintptr_t top_shadow = MemToShadow(top);
  uintptr_t bot_shadow = MemToShadow(bottom);
  memset((void*)bot_shadow, 0, top_shadow - bot_shadow);
}

extern "C" void longjmp(void *env, int val) {
  UnpoisonStackFromHereToTop();
  real_longjmp(env, val);
}

extern "C" void siglongjmp(void *env, int val) {
  UnpoisonStackFromHereToTop();
  real_siglongjmp(env, val);
}

extern "C" void __cxa_throw(void *a, void *b, void *c) {
  UnpoisonStackFromHereToTop();
  real_cxa_throw(a, b, c);
}

// -------------------------- Mac OS X memory interception-------- {{{1
// The following code was partially taken from Google Perftools,
// http://code.google.com/p/google-perftools.
#ifdef __APPLE__
#include <AvailabilityMacros.h>

// We need to provide wrappers around all the libc functions.
namespace {
// TODO(glider): the mz_* functions should be united with the Linux wrappers,
// as they are basically copied from there.
size_t mz_size(malloc_zone_t* zone, const void* ptr) {
  // Check whether this pointer belongs to the original malloc zone.
  // We cannot just call malloc_zone_from_ptr(), because it in turn calls our mz_size().
  if (system_malloc_zone) {
    if ((system_malloc_zone->size)(system_malloc_zone, ptr)) return 0;
  }
  // We cross our fingers, because |p| may belong to unmapped memory.
  Ptr *p = (Ptr*)((uintptr_t*)(ptr) - F_red_zone_words);
  if (p->magic == Ptr::kMallocedMagic) {
    return p->size;
  } else {
    return 0;
  }
}

void* mz_malloc(malloc_zone_t* zone, size_t size) {
  if (!asan_inited) {
    CHECK(system_malloc_zone);
    return malloc_zone_malloc(system_malloc_zone, size);
  }
  if (tl_need_real_malloc) {
    void *res = real_malloc(size);
    // Printf("real_malloc: "PP" %ld\n", res, size);
    return res;
  }
  GET_STACK_TRACE_HERE_FOR_MALLOC;
  Ptr *p = asan_memalign(size, 0, stack);
  return p->raw_ptr();
}

void* mz_calloc(malloc_zone_t* zone, size_t nmemb, size_t size) {
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

void* mz_valloc(malloc_zone_t* zone, size_t size) {
  UNIMPLEMENTED();
  return NULL;
}

void mz_free(malloc_zone_t* zone, void* ptr) {
  if (tl_need_real_malloc) {
    // Printf("real_free "PP"\n", ptr);
    real_free(ptr);
    return;
  };
  GET_STACK_TRACE_HERE_FOR_FREE(ptr);
  asan_free(ptr, stack);
}

void* mz_realloc(malloc_zone_t* zone, void* ptr, size_t size) {
  if (tl_need_real_malloc) {
    void *res = real_realloc(ptr, size);
    // Printf("real_malloc: "PP" "PP" %ld\n", res, ptr, size);
    return res;
  }
  GET_STACK_TRACE_HERE_FOR_MALLOC;
  return asan_realloc(ptr, size, stack);
}

void* mz_memalign(malloc_zone_t* zone, size_t align, size_t size) {
  UNIMPLEMENTED();
  return NULL;
}

void mz_destroy(malloc_zone_t* zone) {
  // A no-op -- we will not be destroyed!
}

// malloc_introspection callbacks.  I'm not clear on what all of these do.
kern_return_t mi_enumerator(task_t task, void *,
                            unsigned type_mask, vm_address_t zone_address,
                            memory_reader_t reader,
                            vm_range_recorder_t recorder) {
  // Should enumerate all the pointers we have.  Seems like a lot of work.
  return KERN_FAILURE;
}

size_t mi_good_size(malloc_zone_t *zone, size_t size) {
  // I think it's always safe to return size, but we maybe could do better.
  return size;
}

boolean_t mi_check(malloc_zone_t *zone) {
  UNIMPLEMENTED();
  return true;
}

void mi_print(malloc_zone_t *zone, boolean_t verbose) {
  UNIMPLEMENTED();
  return;
}

void mi_log(malloc_zone_t *zone, void *address) {
  // I don't think we support anything like this
}

void mi_force_lock(malloc_zone_t *zone) {
  // Hopefully unneeded by us!
}

void mi_force_unlock(malloc_zone_t *zone) {
  // Hopefully unneeded by us!
}

void mi_statistics(malloc_zone_t *zone, malloc_statistics_t *stats) {
  // TODO(csilvers): figure out how to fill these out
  // TODO(glider): port this from tcmalloc when ready.
  stats->blocks_in_use = 0;
  stats->size_in_use = 0;
  stats->max_size_in_use = 0;
  stats->size_allocated = 0;
}

boolean_t mi_zone_locked(malloc_zone_t *zone) {
  return false;  // Hopefully unneeded by us!
}

}  // unnamed namespace

static void ReplaceSystemAlloc() {
  static malloc_introspection_t asan_introspection;
  memset(&asan_introspection, 0, sizeof(asan_introspection));

  asan_introspection.enumerator = &mi_enumerator;
  asan_introspection.good_size = &mi_good_size;
  asan_introspection.check = &mi_check;
  asan_introspection.print = &mi_print;
  asan_introspection.log = &mi_log;
  asan_introspection.force_lock = &mi_force_lock;
  asan_introspection.force_unlock = &mi_force_unlock;

  static malloc_zone_t asan_zone;
  memset(&asan_zone, 0, sizeof(malloc_zone_t));

  // Start with a version 4 zone which is used for OS X 10.4 and 10.5.
  asan_zone.version = 4;
  asan_zone.zone_name = "asan";
  asan_zone.size = &mz_size;
  asan_zone.malloc = &mz_malloc;
  asan_zone.calloc = &mz_calloc;
  asan_zone.valloc = &mz_valloc;
  asan_zone.free = &mz_free;
  asan_zone.realloc = &mz_realloc;
  asan_zone.destroy = &mz_destroy;
  asan_zone.batch_malloc = NULL;
  asan_zone.batch_free = NULL;
  asan_zone.introspect = &asan_introspection;

  // from AvailabilityMacros.h
#if defined(MAC_OS_X_VERSION_10_6) && \
    MAC_OS_X_VERSION_MAX_ALLOWED >= MAC_OS_X_VERSION_10_6
  // Switch to version 6 on OSX 10.6 to support memalign.
  asan_zone.version = 6;
  asan_zone.free_definite_size = NULL;
  asan_zone.memalign = &mz_memalign;
  asan_introspection.zone_locked = &mi_zone_locked;

  // Request the default purgable zone to force its creation. The
  // current default zone is registered with the purgable zone for
  // doing tiny and small allocs.  Sadly, it assumes that the default
  // zone is the szone implementation from OS X and will crash if it
  // isn't.  By creating the zone now, this will be true and changing
  // the default zone won't cause a problem.  (OS X 10.6 and higher.)
  malloc_default_purgeable_zone();
#endif

  // Register the ASan zone. At this point, it will not be the
  // default zone.
  malloc_zone_register(&asan_zone);

  // Unregister and reregister the default zone.  Unregistering swaps
  // the specified zone with the last one registered which for the
  // default zone makes the more recently registered zone the default
  // zone.  The default zone is then re-registered to ensure that
  // allocations made from it earlier will be handled correctly.
  // Things are not guaranteed to work that way, but it's how they work now.
  system_malloc_zone = malloc_default_zone();
  malloc_zone_unregister(system_malloc_zone);
  malloc_zone_register(system_malloc_zone);
}

#endif

// -------------------------- Run-time entry ------------------- {{{1
static void PrintUnwinderHint() {
  if (F_fast_unwind) {
    Printf("HINT: if your stack trace looks short or garbled, "
           "use ASAN_OPTIONS=fast_unwind=0\n");
  }
}

static void     ASAN_OnSIGSEGV(int, siginfo_t *siginfo, void *context) {
  uintptr_t addr = (uintptr_t)siginfo->si_addr;
#if __WORDSIZE == 64
  // If we trapped while accessing an address that looks like shadow
  // -- just map that page. On 32-bits all shadow is pre-mapped.
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
#endif

  Printf("==%d== ERROR: AddressSanitizer crashed on unknown address "PP"\n",
         getpid(), addr);
  Printf("AddressSanitizer can not provide additional info. ABORTING\n");
  PrintCurrentStack();
  ShowStatsAndAbort();
}

static void asan_report_error(uintptr_t pc, uintptr_t bp, uintptr_t sp,
                              uintptr_t addr, unsigned access_size_and_type) {
  bool is_write = access_size_and_type & 8;
  int access_size = 1 << (access_size_and_type & 7);

  if (F_print_malloc_lists) {
    malloc_info.print_lists("OnReport");
  }
  Printf("==================================================================\n");
  PrintUnwinderHint();
  proc_self_maps.Init();
  Printf("==%d== ERROR: AddressSanitizer crashed on address "
         ""PP" at pc 0x%lx bp 0x%lx sp 0x%lx\n",
         getpid(), addr, pc, bp, sp);

  Printf("%s of size %d at "PP" thread T%d\n",
          access_size ? (is_write ? "WRITE" : "READ") : "ACCESS",
          access_size, addr, GetCurrentThread()->tid());

  if (F_debug) {
    PrintBytes("PC: ",(uintptr_t*)pc);
  }

  PrintCurrentStack(pc);

  CHECK(AddrIsInMem(addr));

  malloc_info.DescribeAddress(sp, bp, addr, access_size);

  if (F_print_maps) {
    proc_self_maps.Print();
  }

  uintptr_t shadow_addr = MemToShadow(addr);
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
}

static void     ASAN_OnSIGILL(int, siginfo_t *siginfo, void *context) {
  ucontext_t *ucontext = (ucontext_t*)context;
#ifdef __APPLE__
# if __WORDSIZE == 64
  uintptr_t pc = ucontext->uc_mcontext->__ss.__rip;
  uintptr_t bp = ucontext->uc_mcontext->__ss.__rbp;
  uintptr_t sp = ucontext->uc_mcontext->__ss.__rsp;
  uintptr_t ax = ucontext->uc_mcontext->__ss.__rax;
# else
  uintptr_t pc = ucontext->uc_mcontext->__ss.__eip;
  uintptr_t bp = ucontext->uc_mcontext->__ss.__ebp;
  uintptr_t sp = ucontext->uc_mcontext->__ss.__esp;
  uintptr_t ax = ucontext->uc_mcontext->__ss.__eax;
# endif  // __WORDSIZE
#else  // assume linux
# if __WORDSIZE == 64
  uintptr_t pc = ucontext->uc_mcontext.gregs[REG_RIP];
  uintptr_t bp = ucontext->uc_mcontext.gregs[REG_RBP];
  uintptr_t sp = ucontext->uc_mcontext.gregs[REG_RSP];
  uintptr_t ax = ucontext->uc_mcontext.gregs[REG_RAX];
# else
  uintptr_t pc = ucontext->uc_mcontext.gregs[REG_EIP];
  uintptr_t bp = ucontext->uc_mcontext.gregs[REG_EBP];
  uintptr_t sp = ucontext->uc_mcontext.gregs[REG_ESP];
  uintptr_t ax = ucontext->uc_mcontext.gregs[REG_EAX];
# endif  // __WORDSIZE
#endif

  uintptr_t addr = ax;

  uint8_t *insn = (uint8_t*)pc;
  CHECK(insn[0] == 0x0f && insn[1] == 0x0b);  // ud2
  unsigned access_size_and_type = insn[2] - 0x50;
  CHECK(access_size_and_type < 16);
  asan_report_error(pc, bp, sp, addr, access_size_and_type);
}

// exported functions
#define ASAN_REPORT_ERROR(size_and_type) \
extern "C" void __asan_report_error_ ## size_and_type(uintptr_t addr) { \
  uintptr_t bp = *GET_CURRENT_FRAME();                               \
  uintptr_t pc = GET_CALLER_PC();                                    \
  uintptr_t local_stack;                                             \
  uintptr_t sp = (uintptr_t)&local_stack;                            \
  asan_report_error(pc, bp, sp, addr, size_and_type);                \
}

// handle reads of sizes 1..16
ASAN_REPORT_ERROR(0)
ASAN_REPORT_ERROR(1)
ASAN_REPORT_ERROR(2)
ASAN_REPORT_ERROR(3)
ASAN_REPORT_ERROR(4)
// handle writes of sizes 1..16
ASAN_REPORT_ERROR(8)
ASAN_REPORT_ERROR(9)
ASAN_REPORT_ERROR(10)
ASAN_REPORT_ERROR(11)
ASAN_REPORT_ERROR(12)


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

#ifdef __APPLE__
  ReplaceSystemAlloc();
#endif

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
  F_atexit = IntFlagValue(options, "atexit=", 0);
  F_poison_shadow = IntFlagValue(options, "poison_shadow=", 1);
  F_large_malloc = IntFlagValue(options, "large_malloc=", 1 << 30);
  F_stats = IntFlagValue(options, "stats=", 0);
  F_symbolize = IntFlagValue(options, "symbolize=", 1);
  F_demangle = IntFlagValue(options, "demangle=", 1);
  F_debug = IntFlagValue(options, "debug=", 0);
  F_fast_unwind = IntFlagValue(options, "fast_unwind=", 1);
  F_debug_malloc_size = IntFlagValue(options, "debug_malloc_size=", 0);
  F_mt = IntFlagValue(options, "mt=", 1);
#if __WORDSIZE == 64
  F_protect_shadow = IntFlagValue(options, "protect_shadow=", 0);
#endif

  if (F_atexit) {
    atexit(asan_atexit);
  }

  size_t F_delay_queue_size =
      IntFlagValue(options, "delay_queue_size=", 1UL << 28);
  __asan_quarantine_size = F_delay_queue_size;
  malloc_info.Init(F_delay_queue_size);

  if (F_malloc_context_size > F_red_zone_words)
    F_malloc_context_size = F_red_zone_words;
  CHECK((real_sigaction = (sigaction_f)dlsym(RTLD_NEXT, "sigaction")));
  CHECK((real_signal = (signal_f)dlsym(RTLD_NEXT, "signal")));
  CHECK((real_mmap = (mmap_f)dlsym(RTLD_NEXT, "mmap")));
  CHECK((real_longjmp = (longjmp_f)dlsym(RTLD_NEXT, "longjmp")));
  CHECK((real_siglongjmp = (longjmp_f)dlsym(RTLD_NEXT, "siglongjmp")));
  CHECK((real_cxa_throw = (cxa_throw_f)dlsym(RTLD_NEXT, "__cxa_throw")));
  CHECK((real_pthread_create = (pthread_create_f)dlsym(RTLD_NEXT, "pthread_create")));
#ifndef __APPLE__
  CHECK((real_malloc = (malloc_f)dlsym(RTLD_NEXT, "malloc")));
  CHECK((real_realloc = (realloc_f)dlsym(RTLD_NEXT, "realloc")));
  CHECK((real_free = (free_f)dlsym(RTLD_NEXT, "free")));
#endif

  // Set the SIGSEGV handler.
  {
    struct sigaction sigact;
    memset(&sigact, 0, sizeof(sigact));
    sigact.sa_sigaction = ASAN_OnSIGSEGV;
    sigact.sa_flags = SA_SIGINFO;
    CHECK(0 == real_sigaction(SIGSEGV, &sigact, 0));
  }

#ifdef __APPLE__
  // Set the SIGBUS handler. Mac OS may generate either SIGSEGV or SIGBUS.
  {
    struct sigaction sigact;
    memset(&sigact, 0, sizeof(sigact));
    sigact.sa_sigaction = ASAN_OnSIGSEGV;
    sigact.sa_flags = SA_SIGINFO;
    CHECK(0 == real_sigaction(SIGBUS, &sigact, 0));
  }
#endif

  // Set the SIGILL handler.
  {
    struct sigaction sigact;
    memset(&sigact, 0, sizeof(sigact));
    sigact.sa_sigaction = ASAN_OnSIGILL;
    sigact.sa_flags = SA_SIGINFO;
    CHECK(0 == real_sigaction(SIGILL, &sigact, 0));
  }

  //proc_self_maps.Init();

#if __WORDSIZE == 32
  {
    // mmap the low shadow.
    mmap_range(kLowShadowBeg, kLowShadowEnd, "LowShadow");
    // mmap the high shadow.
    mmap_range(kHighShadowBeg, kHighShadowEnd, "HighShadow");
  }
#else  // __WORDSIZE == 64
  {
    uintptr_t first_shadow_page = kCompactShadowMask;
    mmap_pages(first_shadow_page, 1, "First shadow page");
  }
#endif  // __WORDSIZE == 64

  if (F_protect_shadow) {
    // protect the gap between low and high shadow
    protect_range(kShadowGapBeg, kShadowGapEnd);
  }

#ifdef __APPLE__
  CHECK(0 == pthread_key_create(&g_tls_key, 0));
  tls_key_created = true;
#endif  // __APPLE__

  AsanThread *t = (AsanThread*)real_malloc(sizeof(AsanThread));
  new (t) AsanThread(0, 0, 0, 0);
  SetCurrentThread(t);
#ifdef __APPLE__
  g_thread_0 = GetCurrentThread();
#endif  
  t->ThreadStart();

  asan_inited = 1;

  if (F_v) {
    Printf("==%d== AddressSanitizer r%s Init done ***\n", getpid(), ASAN_REVISION);
    Printf("|| `["PP", "PP"]` || HighMem    ||\n", kHighMemBeg, kHighMemEnd);
    Printf("|| `["PP", "PP"]` || HighShadow ||\n", kHighShadowBeg, kHighShadowEnd);
    Printf("|| `["PP", "PP"]` || ShadowGap ||\n", kShadowGapBeg, kShadowGapEnd);
    Printf("|| `["PP", "PP"]` || LowShadow  ||\n", kLowShadowBeg, kLowShadowEnd);
    Printf("|| `["PP", "PP"]` || LowMem     ||\n", kLowMemBeg, kLowMemEnd);
    Printf("MemToShadow(shadow): "PP" "PP" "PP" "PP"\n",
           MEM_TO_SHADOW(kLowShadowBeg),
           MEM_TO_SHADOW(kLowShadowEnd),
           MEM_TO_SHADOW(kHighShadowBeg),
           MEM_TO_SHADOW(kHighShadowEnd));
    Printf("red_zone_words=%ld\n", F_red_zone_words);
    Printf("malloc_context_size=%ld\n", (int)F_malloc_context_size);
    Printf("fast_unwind=%d\n", (int)F_fast_unwind);
  }
}

void __asan_check_failed(const char *cond, const char *file, int line) {
  Printf("CHECK failed: %s at %s:%d\n", cond, file, line);
  PrintCurrentStack();
  ShowStatsAndAbort();
}
