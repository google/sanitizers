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

#include "asan_internal.h"

#include <sys/mman.h>
#include <unistd.h>

namespace __asan {

// No-op. Mac does not support static linkage anyway.
void *AsanDoesNotSupportStaticLinkage() {
  return NULL;
}

void *asan_mmap(void *addr, size_t length, int prot, int flags,
                                    int fd, uint64_t offset) {
  return mmap(addr, length, prot, flags, fd, offset);
}

}  // namespace __asan
