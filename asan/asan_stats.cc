//===-- asan_stats.cc ------------*- C++ -*-===//
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
// Code related to statistics collected by AddressSanitizer.
//===----------------------------------------------------------------------===//
#include "asan_interceptors.h"
#include "asan_interface.h"
#include "asan_internal.h"
#include "asan_lock.h"
#include "asan_stats.h"
#include "asan_thread_registry.h"

namespace __asan {

AsanStats::AsanStats() {
  CHECK(real_memset != NULL);
  real_memset(this, 0, sizeof(AsanStats));
}

void AsanStats::FlushToStats(AsanStats *stats) {
  // AsanStats consists of variables of type size_t only.
  size_t *dst = (size_t*)stats;
  size_t *src = (size_t*)this;
  size_t num_fields = sizeof(AsanStats) / sizeof(size_t);
  for (size_t i = 0; i < num_fields; i++) {
    dst[i] += src[i];
    src[i] = 0;
  }
}

static void PrintMallocStatsArray(const char *prefix,
                                  size_t (&array)[kNumberOfSizeClasses]) {
  Printf("%s", prefix);
  for (size_t i = 0; i < kNumberOfSizeClasses; i++) {
    if (!array[i]) continue;
    Printf("%ld:%ld; ", i, array[i]);
  }
  Printf("\n");
}

void AsanStats::Print() {
  Printf("Stats: %ldM malloced (%ldM for red zones) by %ld calls\n",
         malloced>>20, malloced_redzones>>20, mallocs);
  Printf("Stats: %ldM realloced by %ld calls\n", realloced>>20, reallocs);
  Printf("Stats: %ldM freed by %ld calls\n", freed>>20, frees);
  Printf("Stats: %ldM really freed by %ld calls\n",
         really_freed>>20, real_frees);
  Printf("Stats: %ldM (%ld full pages) mmaped in %ld calls\n",
         mmaped>>20, mmaped / kPageSize, mmaps);

  PrintMallocStatsArray("  mmaps   by size class: ", mmaped_by_size);
  PrintMallocStatsArray("  mallocs by size class: ", malloced_by_size);
  PrintMallocStatsArray("  frees   by size class: ", freed_by_size);
  PrintMallocStatsArray("  rfrees  by size class: ", really_freed_by_size);
  Printf("Stats: malloc large: %ld small slow: %ld\n",
         malloc_large, malloc_small_slow);
}

static inline void PrintDisabledStatsHint() {
  static bool disabled_stats_hint_printed = false;
  if (!FLAG_stats && !disabled_stats_hint_printed) {
    Printf("HINT: ASan doesn't collect stats. Set ASAN_OPTIONS=stats=1 or "
           "call __asan_enable_statistics(true)\n");
    disabled_stats_hint_printed = true;
  }
}

static void PrintAccumulatedStats() {
  AsanStats stats = asanThreadRegistry().GetAccumulatedStats();
  // Use lock to keep reports from mixing up.
  static AsanLock print_lock;
  ScopedLock lock(&print_lock);
  PrintDisabledStatsHint();
  stats.Print();
}

}  // namespace __asan

// ---------------------- Interface ---------------- {{{1
using namespace __asan;  // NOLINT

size_t __asan_get_current_allocated_bytes() {
  return asanThreadRegistry().GetCurrentAllocatedBytes();
}

bool __asan_enable_statistics(bool enable) {
  bool old_flag = FLAG_stats;
  FLAG_stats = enable;
  return old_flag;
}

void __asan_print_accumulated_stats() {
  PrintAccumulatedStats();
}
