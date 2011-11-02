//===-- asan_globals.cc ------------*- C++ -*-===//
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
// Handle globals.
//===----------------------------------------------------------------------===//
#include "asan_interceptors.h"
#include "asan_interface.h"
#include "asan_internal.h"
#include "asan_lock.h"
#include "asan_mapping.h"
#include "asan_stack.h"
#include "asan_stats.h"
#include "asan_thread.h"

#include <ctype.h>
#include <map>

namespace __asan {

// We create right redzones for globals and keep the globals in a map.
struct Global {
  uintptr_t beg;  // Address of the global.
  size_t size;    // Size of the global.
  const char *name;

  void PoisonRedZones() {
    uintptr_t shadow = MemToShadow(beg);
    size_t ShadowRZSize = kGlobalAndStackRedzone >> SHADOW_SCALE;
    CHECK(ShadowRZSize == 1 || ShadowRZSize == 2 || ShadowRZSize == 4);
    // full right redzone
    uintptr_t right_rz2_offset = ShadowRZSize *
        ((size + kGlobalAndStackRedzone - 1) / kGlobalAndStackRedzone);
    real_memset((uint8_t*)shadow + right_rz2_offset,
                kAsanGlobalRedzoneMagic, ShadowRZSize);
    if ((size % kGlobalAndStackRedzone) != 0) {
      // partial right redzone
      uint64_t right_rz1_offset =
          ShadowRZSize * (size / kGlobalAndStackRedzone);
      CHECK(right_rz1_offset == right_rz2_offset - ShadowRZSize);
      PoisonShadowPartialRightRedzone((uint8_t*)(shadow + right_rz1_offset),
                                      size % kGlobalAndStackRedzone,
                                      kGlobalAndStackRedzone,
                                      SHADOW_GRANULARITY,
                                      kAsanGlobalRedzoneMagic);
    }
  }

  static size_t GetAlignedSize(size_t size) {
    return ((size + kGlobalAndStackRedzone - 1) / kGlobalAndStackRedzone)
        * kGlobalAndStackRedzone;
  }

  size_t GetAlignedSize() {
    return GetAlignedSize(this->size);
  }

  // Check if the global is a zero-terminated ASCII string. If so, print it.
  void PrintIfASCII() {
    for (size_t p = beg; p < beg + size - 1; p++) {
      if (!isascii(*(char*)p)) return;
    }
    if (*(char*)(beg + size - 1) != 0) return;
    Printf("  '%s' is ascii string '%s'\n", name, beg);
  }

  bool DescribeAddrIfMyRedZone(uintptr_t addr) {
    if (addr < beg - kGlobalAndStackRedzone) return false;
    if (addr >= beg + GetAlignedSize() + kGlobalAndStackRedzone) return false;
    Printf("%p is located ", addr);
    if (addr < beg) {
      Printf("%d bytes to the left", beg - addr);
    } else if (addr >= beg + size) {
      Printf("%d bytes to the right", addr - (beg + size));
    } else {
      Printf("%d bytes inside", addr - beg);  // Can it happen?
    }
    Printf(" of global variable '%s' (0x%lx) of size %ld\n", name, beg, size);
    PrintIfASCII();
    return true;
  }

  static AsanLock mu_;
};

AsanLock Global::mu_;

typedef std::map<uintptr_t, Global> MapOfGlobals;
static MapOfGlobals *g_all_globals = NULL;

bool DescribeAddrIfGlobal(uintptr_t addr) {
  if (!FLAG_report_globals) return false;
  ScopedLock lock(&Global::mu_);
  if (!g_all_globals) return false;
  bool res = false;
  // Just iterate. May want to use binary search instead.
  for (MapOfGlobals::iterator i = g_all_globals->begin(),
       end = g_all_globals->end(); i != end; ++i) {
    Global &g = i->second;
    CHECK(i->first == g.beg);
    if (FLAG_report_globals >= 2)
      Printf("Search Global: beg=%p size=%ld name=%s\n",
             g.beg, g.size, g.name);
    res |= g.DescribeAddrIfMyRedZone(addr);
  }
  return res;
}

}  // namespace __asan

// ---------------------- Interface ---------------- {{{1
using namespace __asan;  // NOLINT

// exported function.
// Register a global variable by its address, size and name.
// This function may be called more than once for every global
// so we store the globals in a map.
void __asan_register_global(uintptr_t addr, size_t size,
                            const char *name) {
  CHECK(asan_inited);
  if (!FLAG_report_globals) return;
  ScopedLock lock(&Global::mu_);
  if (!g_all_globals)
    g_all_globals = new MapOfGlobals;
  CHECK(AddrIsInMem(addr));
  Global g;
  g.size = size;
  g.beg = addr;
  g.name = name;
  if (FLAG_report_globals >= 2)
    Printf("Added Global: beg=%p size=%ld name=%s\n",
           g.beg, g.size, g.name);
  g.PoisonRedZones();
  (*g_all_globals)[addr] = g;
}
