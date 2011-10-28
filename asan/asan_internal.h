//===-- asan_internal.h -----------------------------------------*- C++ -*-===//
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
// ASan-private header which defines various general utilities.
//===----------------------------------------------------------------------===//
#ifndef ASAN_INTERNAL_H
#define ASAN_INTERNAL_H

#include <stdint.h>  // for __WORDSIZE
#include <stdlib.h>  // for size_t

// All internal functions in asan reside inside the __asan namespace
// to avoid namespace collisions with the user programs.
// Seperate namespace also makes it simpler to distinguish the asan run-time
// functions from the instrumented user code in a profile.
namespace __asan {

class AsanThread;
class AsanStackTrace;

void ReplaceSystemMalloc();
void CheckFailed(const char *cond, const char *file, int line);
void *asan_mmap(void *addr, size_t length, int prot, int flags,
                                    int fd, uint64_t offset);
void ShowStatsAndAbort();
bool DescribeAddrIfGlobal(uintptr_t addr);
void *AsanDoesNotSupportStaticLinkage();

void Printf(const char *format, ...);

extern size_t FLAG_quarantine_size;
extern int    FLAG_demangle;
extern bool   FLAG_symbolize;
extern int    FLAG_v;
extern bool   FLAG_mt;
extern size_t FLAG_redzone;
extern int    FLAG_debug;
extern bool   FLAG_poison_shadow;
extern int    FLAG_report_globals;
extern size_t FLAG_malloc_context_size;
extern bool   FLAG_stats;
extern bool   FLAG_replace_str;
extern bool   FLAG_replace_intrin;
extern bool   FLAG_fast_unwind;

extern int __asan_inited;
// Used to avoid infinite recursion in __asan_init().
extern bool __asan_init_is_running;

enum LinkerInitialized { LINKER_INITIALIZED = 0 };

#define CHECK(cond) do { if (!(cond)) { \
  CheckFailed(#cond, __FILE__, __LINE__); \
}}while(0)

#if __WORDSIZE == 64
  #define PP "0x%012lx"
#else
  #define PP "0x%08lx"
#endif

#define ASAN_ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))

const size_t kWordSize = __WORDSIZE / 8;
const size_t kWordSizeInBits = 8 * kWordSize;
const size_t kPageSizeBits = 12;
const size_t kPageSize = 1UL << kPageSizeBits;

#define GET_CALLER_PC() (uintptr_t)__builtin_return_address(0)
#define GET_CURRENT_FRAME() (uintptr_t)__builtin_frame_address(0)

#define GET_BP_PC_SP \
  uintptr_t bp = GET_CURRENT_FRAME();              \
  uintptr_t pc = GET_CALLER_PC();                  \
  uintptr_t local_stack;                           \
  uintptr_t sp = (uintptr_t)&local_stack;

// These magic values are written to shadow for better error reporting.
const int kAsanHeapLeftRedzoneMagic = 0xfa;
const int kAsanHeapRightRedzoneMagic = 0xfb;
const int kAsanHeapFreeMagic = 0xfd;
const int kAsanStackLeftRedzoneMagic = 0xf1;
const int kAsanStackMidRedzoneMagic = 0xf2;
const int kAsanStackRightRedzoneMagic = 0xf3;
const int kAsanStackPartialRedzoneMagic = 0xf4;
const int kAsanStackAfterReturnMagic = 0xf5;
const int kAsanGlobalRedzoneMagic = 0xf9;

// Poison the shadow memory which corresponds to 'redzone_size' bytes
// of the original memory, where first 'size' bytes are addressable.
static inline void
PoisonShadowPartialRightRedzone(unsigned char *shadow,
                                uintptr_t size,
                                uintptr_t redzone_size,
                                uintptr_t shadow_granularity,
                                unsigned char magic) {
  for (uintptr_t i = 0; i < redzone_size;
       i+= shadow_granularity, shadow++) {
    if (i + shadow_granularity <= size) {
      *shadow = 0;  // fully addressable
    } else if (i >= size) {
      *shadow = (shadow_granularity == 128) ? 0xff : magic;  // unaddressable
    } else {
      *shadow = size - i;  // first size-i bytes are addressable
    }
  }
}

// -------------------------- Atomic ---------------- {{{1
static inline int AtomicInc(int *a) {
  if (!FLAG_mt) return ++(*a);
  return __sync_add_and_fetch(a, 1);
}

static inline int AtomicDec(int *a) {
  if (!FLAG_mt) return --(*a);
  return __sync_add_and_fetch(a, -1);
}

}  // namespace __asan

#endif  // ASAN_INTERNAL_H
