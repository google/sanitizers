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

#include "asan_allocator.h"
#include "asan_int.h"
#include "asan_rtl.h"
#include "asan_lock.h"
#include "asan_mapping.h"
#include "asan_stack.h"
#include "asan_stats.h"
#include "asan_thread.h"


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
#include <dlfcn.h>
// must not include <setjmp.h>


#define UNIMPLEMENTED() CHECK("unimplemented" && 0)

// -------------------------- Flags ------------------------- {{{1
static const size_t kMallocContextSize = 30;
static int    __asan_flag_atexit;
static bool   __asan_flag_fast_unwind;

size_t __asan_flag_redzone_words;  // multiple of 8
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


#if __WORDSIZE == 32
static const int __asan_flag_protect_shadow = 1;
#else
static int __asan_flag_protect_shadow;
#endif

// -------------------------- Printf ---------------- {{{1
static FILE *asan_out = NULL;

void __asan_printf(const char *format, ...) {
  const int kLen = 1024 * 4;
  char buffer[kLen];
  va_list args;
  va_start(args, format);
  vsnprintf(buffer, kLen, format, args);
  fwrite(buffer, 1, strlen(buffer), asan_out);
  fflush(asan_out);
  va_end(args);
}


// -------------------------- Globals --------------------- {{{1
static int asan_inited;

__attribute__((weak)) __attribute__((visibility("default"))) uintptr_t __asan_mapping_scale;
__attribute__((weak)) __attribute__((visibility("default"))) uintptr_t __asan_mapping_offset;


#if __WORDSIZE == 64
static uintptr_t
  mapped_clusters[(1UL << kPossiblePageClustersBits) / kWordSizeInBits];
static AsanLock shadow_lock;
#endif

// -------------------------- Interceptors ---------------- {{{1
typedef int (*sigaction_f)(int signum, const struct sigaction *act,
                           struct sigaction *oldact);
typedef sig_t (*signal_f)(int signum, sig_t handler);
typedef void (*longjmp_f)(void *env, int val);
typedef void (*cxa_throw_f)(void *, void *, void *);
typedef int (*pthread_create_f)(pthread_t *thread, const pthread_attr_t *attr,
                              void *(*start_routine) (void *), void *arg);

static sigaction_f      real_sigaction;
static signal_f         real_signal;
static longjmp_f        real_longjmp;
static longjmp_f        real_siglongjmp;
static cxa_throw_f      real_cxa_throw;
static pthread_create_f real_pthread_create;

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

#if __WORDSIZE == 64
  Printf("Stats: %ldM of shadow memory allocated in %ld clusters (%ldM each)\n",
         ((low_shadow_maps + high_shadow_maps) * kPageClusterSize * kPageSize)>>20,
         low_shadow_maps + high_shadow_maps,
         (kPageClusterSize * kPageSize) >> 20);
#endif
}

AsanStats __asan_stats;

// -------------------------- Misc ---------------- {{{1
static void ShowStatsAndAbort() {
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
// given sp and bp, find the frame to which addr belongs.
static int TryToFindFrameForStackAddress(uintptr_t sp, uintptr_t bp,
                                         uintptr_t addr) {
  if (bp == 0 || sp == 0)  return -1;
  AsanThread *t = AsanThread::GetCurrent();
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

#define GET_STACK_TRACE_HERE_FOR_MALLOC         \
  GET_STACK_TRACE_HERE(__asan_flag_malloc_context_size, __asan_flag_fast_unwind)

#define GET_STACK_TRACE_HERE_FOR_FREE(ptr) \
  GET_STACK_TRACE_HERE(__asan_flag_malloc_context_size, __asan_flag_fast_unwind)



static void *asan_thread_start(void *arg) {
  AsanThread *t= (AsanThread*)arg;
  AsanThread::SetCurrent(t);
  return t->ThreadStart();
}

// ---------------------- AddressSanitizer malloc -------------------- {{{1
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

#if __WORDSIZE == 32
// mmap range [beg, end]
static char *mmap_range(uintptr_t beg, uintptr_t end, const char *mem_type) {
  CHECK((beg % kPageSize) == 0);
  CHECK(((end + 1) % kPageSize) == 0);
  // Printf("mmap_range "PP" "PP" %ld\n", beg, end, (end - beg) / kPageSize);
  return mmap_pages(beg, (end - beg + 1) / kPageSize, mem_type);
}
#else  // __WORDSIZE == 64
static char *mmap_low_shadow(size_t start_page, size_t n_pages) {
  CHECK(AddrIsInLowShadow(start_page));
  __asan_stats.low_shadow_maps++;
  return mmap_pages(start_page, n_pages, "low shadow memory");
}

static char *mmap_high_shadow(size_t start_page, size_t n_pages) {
  CHECK(AddrIsInHighShadow(start_page));
  __asan_stats.high_shadow_maps++;
  return mmap_pages(start_page, n_pages, "high shadow memory");
}
#endif

// protect range [beg, end]
static void protect_range(uintptr_t beg, uintptr_t end) {
  CHECK((beg % kPageSize) == 0);
  CHECK(((end+1) % kPageSize) == 0);
  // Printf("protect_range "PP" "PP" %ld\n", beg, end, (end - beg) / kPageSize);
  void *res = __asan_mmap((void*)beg, end - beg + 1,
                   PROT_NONE,
                   MAP_PRIVATE | MAP_ANON | MAP_FIXED, 0, 0);
  CHECK(res == (void*)beg);
}

// We create right redzones for globals and keep the gobals in a linked list.
struct Global {
  Global *next;   // Next in the list.
  uintptr_t beg;  // Address of the global.
  size_t size;    // Size of the global.
  const char *name;

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
    Printf(" of global variable '%s' (%lx) of size %ld\n", name, beg, size);
    return true;
  }

  static AsanLock mu_;
};

AsanLock Global::mu_;

static Global *g_globals_list;

__attribute__((noinline))
static bool DescribeAddrIfGlobal(uintptr_t addr) {
  if (!__asan_flag_report_globals) return false;
  ScopedLock lock(&Global::mu_);
  bool res = false;
  for (Global *g = g_globals_list; g; g = g->next) {
    if (__asan_flag_report_globals >= 2)
      Printf("Search Global: "PP" beg="PP" size=%ld name=%s\n", g, g->beg, g->size, g->name);
    res |= g->DescribeAddrIfMyRedZone(addr);
    CHECK(g != g->next);
  }
  return res;
}

// exported function
extern "C" void __asan_register_global(uintptr_t addr, size_t size, const char *name) {
  __asan_init();
  if (!__asan_flag_report_globals) return;
  ScopedLock lock(&Global::mu_);
  CHECK(AddrIsInMem(addr));
  // uintptr_t shadow = MemToShadow(addr);
  // Printf("global: "PP"  %ld \n", addr, size);
  uintptr_t aligned_size =
      ((size + kAsanRedzone - 1) / kAsanRedzone) * kAsanRedzone;
  Global *g = (Global*)(addr + aligned_size);
  if (g->beg || g->size || g->name) return;  // we already inserted this one.
  g->next = g_globals_list;
  g->size = size;
  g->beg = addr;
  g->name = name;
  g_globals_list = g;
  if (__asan_flag_report_globals >= 2)
    Printf("Added Global: "PP" beg="PP" size=%ld name=%s\n", g, g->beg, g->size, g->name);
  g->PoisonRedZones();
}

__attribute__((noinline))
static void DescribeAddress(uintptr_t sp, uintptr_t bp,
                            uintptr_t addr, uintptr_t access_size) {
  // Check if this is a global.
  if (DescribeAddrIfGlobal(addr))
    return;

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
  // finally, check if this is a heap.
  __asan_describe_heap_address(addr, access_size);
}



// -------------------------- Interceptors ------------------- {{{1

extern "C"
void *malloc(size_t size) {
  GET_STACK_TRACE_HERE_FOR_MALLOC;
  return __asan_malloc(size, &stack);
}

extern "C"
void free(void *ptr) {
  GET_STACK_TRACE_HERE_FOR_FREE(ptr);
  __asan_free(ptr, &stack);
}

extern "C"
void *calloc(size_t nmemb, size_t size) {
  GET_STACK_TRACE_HERE_FOR_MALLOC;
  if (!asan_inited) {
    // Hack: dlsym calls calloc before real_calloc is retrieved from dlsym.
    const size_t kCallocPoolSize = 1024;
    static uintptr_t calloc_memory_for_dlsym[kCallocPoolSize];
    static size_t allocated;
    size_t size_in_words = ((nmemb * size) + kWordSize - 1) / kWordSize;
    void *mem = (void*)&calloc_memory_for_dlsym[allocated];
    allocated += size_in_words;
    CHECK(allocated < kCallocPoolSize);
    return mem;
  }
  return __asan_calloc(nmemb, size, &stack);
}

extern "C"
void *realloc(void *ptr, size_t size) {
  GET_STACK_TRACE_HERE_FOR_MALLOC;
  return __asan_realloc(ptr, size, &stack);
}

extern "C"
void *memalign(size_t boundary, size_t size) {
  GET_STACK_TRACE_HERE_FOR_MALLOC;
  return __asan_memalign(boundary, size, &stack);
}

extern "C"
int posix_memalign(void **memptr, size_t alignment, size_t size) {
  GET_STACK_TRACE_HERE_FOR_MALLOC;
  // Printf("posix_memalign: %lx %ld\n", alignment, size);
  return __asan_posix_memalign(memptr, alignment, size, &stack);
}
extern "C"
void *valloc(size_t size) {
  GET_STACK_TRACE_HERE_FOR_MALLOC;
  return __asan_valloc(size, &stack);
}

#if 1
#define OPERATOR_NEW_BODY \
  GET_STACK_TRACE_HERE_FOR_MALLOC;\
  return __asan_memalign(0, size, &stack);

void *operator new(size_t size) { OPERATOR_NEW_BODY; }
void *operator new[](size_t size) { OPERATOR_NEW_BODY; }
void *operator new(size_t size, std::nothrow_t const&) { OPERATOR_NEW_BODY; }
void *operator new[](size_t size, std::nothrow_t const&) { OPERATOR_NEW_BODY; }

#define OPERATOR_DELETE_BODY \
  GET_STACK_TRACE_HERE_FOR_FREE(ptr);\
  __asan_free(ptr, &stack);

void operator delete(void *ptr) { OPERATOR_DELETE_BODY; }
void operator delete[](void *ptr) { OPERATOR_DELETE_BODY; }
void operator delete(void *ptr, std::nothrow_t const&) { OPERATOR_DELETE_BODY; }
void operator delete[](void *ptr, std::nothrow_t const&) { OPERATOR_DELETE_BODY; }
#endif

extern "C" int pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                                void *(*start_routine) (void *), void *arg) {
  GET_STACK_TRACE_HERE(kStackTraceMax, /*fast_unwind*/false);
  AsanThread *t = (AsanThread*)__asan_malloc(sizeof(AsanThread), &stack);
  new (t) AsanThread(AsanThread::GetCurrent(), start_routine, arg, &stack);
  return real_pthread_create(thread, attr, asan_thread_start, t);
}

extern "C"
sig_t signal(int signum, sig_t handler) {
#ifdef __APPLE__
  if (signum != SIGSEGV && signum != SIGBUS && signum != SIGILL) {
#else
  if (signum != SIGSEGV && signum != SIGILL) {
#endif
    return real_signal(signum, handler);
  }
  return NULL;
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
  uintptr_t top = AsanThread::GetCurrent()->stack_top();
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
#include <malloc/malloc.h>

static malloc_zone_t *system_malloc_zone = NULL;

// We need to provide wrappers around all the libc functions.
namespace {
// TODO(glider): the mz_* functions should be united with the Linux wrappers,
// as they are basically copied from there.
size_t mz_size(malloc_zone_t* zone, const void* ptr) {
  // Check whether this pointer belongs to the original malloc zone.
  // We cannot just call malloc_zone_from_ptr(), because it in turn calls our mz_size().
  if (system_malloc_zone) {
    if ((system_malloc_zone->size)(system_malloc_zone, ptr)) return 0;
#if 0
    // Memory regions owned by ASan are in fact allocated by the system allocator.
    // If this was done using malloc() rather than memalign(), we can find the first
    // byte of the allocation and make sure it's accessible.
    if ((system_malloc_zone->size)(system_malloc_zone, (char*)ptr - __asan_flag_redzone_words)) {
      // TODO(glider): check that the size returned by the system_malloc_zone->size
      // matches our zone size + overhead.
      return __asan_get_allocation_size((char*)ptr - __asan_flag_redzone_words);
    }
#endif  
  }
  return __asan_mz_size(ptr);
}

void* mz_malloc(malloc_zone_t* zone, size_t size) {
  if (!asan_inited) {
    CHECK(system_malloc_zone);
    return malloc_zone_malloc(system_malloc_zone, size);
  }
  GET_STACK_TRACE_HERE_FOR_MALLOC;
  return __asan_memalign(0, size, &stack);
}

void* mz_calloc(malloc_zone_t* zone, size_t nmemb, size_t size) {
  GET_STACK_TRACE_HERE_FOR_MALLOC;
  if (!asan_inited) {
    // Hack: dlsym calls calloc before real_calloc is retrieved from dlsym.
    const size_t kCallocPoolSize = 1024;
    static uintptr_t calloc_memory_for_dlsym[kCallocPoolSize];
    static size_t allocated;
    size_t size_in_words = ((nmemb * size) + kWordSize - 1) / kWordSize;
    void *mem = (void*)&calloc_memory_for_dlsym[allocated];
    allocated += size_in_words;
    CHECK(allocated < kCallocPoolSize);
    return mem;
  }
  return __asan_calloc(nmemb, size, &stack);
}

void* mz_valloc(malloc_zone_t* zone, size_t size) {
  if (!asan_inited) {
    CHECK(system_malloc_zone);
    return malloc_zone_valloc(system_malloc_zone, size);
  }
  GET_STACK_TRACE_HERE_FOR_MALLOC;
  return __asan_memalign(kPageSize, size, &stack);
}

void mz_free(malloc_zone_t* zone, void* ptr) {
  GET_STACK_TRACE_HERE_FOR_FREE(ptr);
  __asan_free(ptr, &stack);
}

void* mz_realloc(malloc_zone_t* zone, void* ptr, size_t size) {
  GET_STACK_TRACE_HERE_FOR_MALLOC;
  return __asan_realloc(ptr, size, &stack);
}

void* mz_memalign(malloc_zone_t* zone, size_t align, size_t size) {
  if (!asan_inited) {
    CHECK(system_malloc_zone);
    return malloc_zone_memalign(system_malloc_zone, align, size);
  }
  GET_STACK_TRACE_HERE_FOR_MALLOC;
  return __asan_memalign(align, size, &stack);
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
  if (__asan_flag_fast_unwind) {
    Printf("HINT: if your stack trace looks short or garbled, "
           "use ASAN_OPTIONS=fast_unwind=0\n");
  }
}

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

    if (__asan_flag_v >= 2)
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
  // Write the first message using the bullet-proof write.
  if (13 != write(2, "ASAN:SIGSEGV\n", 13)) abort();
  GET_STACK_TRACE_HERE(kStackTraceMax, /*fast_unwind*/true);
  uintptr_t pc, sp, bp, ax;
  GetPcSpBpAx(context, &pc, &sp, &bp, &ax);

  Printf("==%d== ERROR: AddressSanitizer crashed on unknown address "PP""
         " (pc %p sp %p bp %p ax %p T%d)\n",
         getpid(), addr, pc, sp, bp, ax, AsanThread::GetCurrent()->tid());
  Printf("AddressSanitizer can not provide additional info. ABORTING\n");
  AsanStackTrace::PrintCurrent(pc);
  Printf("\n");
  stack.PrintStack();  // try fast unwind too.
  ShowStatsAndAbort();
}

static void asan_report_error(uintptr_t pc, uintptr_t bp, uintptr_t sp,
                              uintptr_t addr, unsigned access_size_and_type) {
  bool is_write = access_size_and_type & 8;
  int access_size = 1 << (access_size_and_type & 7);

  Printf("==================================================================\n");
  PrintUnwinderHint();
  Printf("==%d== ERROR: AddressSanitizer crashed on address "
         ""PP" at pc 0x%lx bp 0x%lx sp 0x%lx\n",
         getpid(), addr, pc, bp, sp);

  Printf("%s of size %d at "PP" thread T%d\n",
          access_size ? (is_write ? "WRITE" : "READ") : "ACCESS",
          access_size, addr, AsanThread::GetCurrent()->tid());

  if (__asan_flag_debug) {
    PrintBytes("PC: ",(uintptr_t*)pc);
  }

  AsanStackTrace::PrintCurrent(pc);

  CHECK(AddrIsInMem(addr));

  DescribeAddress(sp, bp, addr, access_size);

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
  __asan_stats.PrintStats();
}

void __asan_init() {
  if (asan_inited) return;
  asan_out = stderr;

#ifdef __APPLE__
  ReplaceSystemAlloc();
#endif

  // flags
  const char *options = getenv("ASAN_OPTIONS");
  __asan_flag_malloc_context_size =
      IntFlagValue(options, "malloc_context_size=", kMallocContextSize);
  CHECK(__asan_flag_malloc_context_size <= kMallocContextSize);

  __asan_flag_v = IntFlagValue(options, "v=", 0);

  __asan_flag_redzone_words = IntFlagValue(options, "red_zone_words=", 16);
  if (__asan_flag_redzone_words & 7) {
    __asan_flag_redzone_words = (__asan_flag_redzone_words + 7) & ~7;
  }
  CHECK(__asan_flag_redzone_words >= 8 && (__asan_flag_redzone_words % 8) == 0);

  __asan_flag_atexit = IntFlagValue(options, "atexit=", 0);
  __asan_flag_poison_shadow = IntFlagValue(options, "poison_shadow=", 1);
  __asan_flag_report_globals = IntFlagValue(options, "report_globals=", 1);
  __asan_flag_large_malloc = IntFlagValue(options, "large_malloc=", 1 << 30);
  __asan_flag_stats = IntFlagValue(options, "stats=", 0);
  __asan_flag_symbolize = IntFlagValue(options, "symbolize=", 1);
  __asan_flag_demangle = IntFlagValue(options, "demangle=", 1);
  __asan_flag_debug = IntFlagValue(options, "debug=", 0);
  __asan_flag_fast_unwind = IntFlagValue(options, "fast_unwind=", 1);
  __asan_flag_mt = IntFlagValue(options, "mt=", 1);
#if __WORDSIZE == 64
  __asan_flag_protect_shadow = IntFlagValue(options, "protect_shadow=", 0);
#endif

  if (__asan_flag_atexit) {
    atexit(asan_atexit);
  }

  __asan_flag_quarantine_size =
      IntFlagValue(options, "quarantine_size=", 1UL << 28);

  CHECK((real_sigaction = (sigaction_f)dlsym(RTLD_NEXT, "sigaction")));
  CHECK((real_signal = (signal_f)dlsym(RTLD_NEXT, "signal")));
  CHECK((real_longjmp = (longjmp_f)dlsym(RTLD_NEXT, "longjmp")));
  CHECK((real_siglongjmp = (longjmp_f)dlsym(RTLD_NEXT, "siglongjmp")));
  CHECK((real_cxa_throw = (cxa_throw_f)dlsym(RTLD_NEXT, "__cxa_throw")));
  CHECK((real_pthread_create = (pthread_create_f)dlsym(RTLD_NEXT, "pthread_create")));

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

  if (__asan_flag_protect_shadow) {
    // protect the gap between low and high shadow
    protect_range(kShadowGapBeg, kShadowGapEnd);
  }

  asan_inited = 1;

  AsanThread::Init();
  AsanThread::GetMain()->ThreadStart();


  if (__asan_flag_v) {
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
    Printf("red_zone_words=%ld\n", __asan_flag_redzone_words);
    Printf("malloc_context_size=%ld\n", (int)__asan_flag_malloc_context_size);
    Printf("fast_unwind=%d\n", (int)__asan_flag_fast_unwind);
    if (&__asan_mapping_scale) {
      Printf("__asan_mapping_scale: %lx\n", __asan_mapping_scale);
    }
    if (&__asan_mapping_offset) {
      Printf("__asan_mapping_offset: %lx\n", __asan_mapping_offset);
    }
  }
}

void __asan_check_failed(const char *cond, const char *file, int line) {
  Printf("CHECK failed: %s at %s:%d\n", cond, file, line);
  AsanStackTrace::PrintCurrent();
  ShowStatsAndAbort();
}
