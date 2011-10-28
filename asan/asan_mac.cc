//===-- asan_mac.cc -----------------------------------------------------===//
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
// Mac-specific details.
//===----------------------------------------------------------------------===//

#include "asan_int.h"

#include <sys/mman.h>
#include <unistd.h>

// No-op. Mac does not support static linkage anyway.
void *__asan_does_not_support_static_linkage() {
}

void *__asan_mmap(void *addr, size_t length, int prot, int flags,
                                    int fd, uint64_t offset) {
  return mmap(addr, length, prot, flags, fd, offset);
}
