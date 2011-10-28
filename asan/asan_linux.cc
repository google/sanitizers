//===-- asan_linux.cc -----------------------------------------------------===//
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
// Linux-specific details.
//===----------------------------------------------------------------------===//

#include "asan_int.h"

#include <elf.h>
#include <link.h>

extern ElfW(Dyn) _DYNAMIC[];

void *__asan_does_not_support_static_linkage() {
  // This will fail to link with -static.
  return &_DYNAMIC;
}
