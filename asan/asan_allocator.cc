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

#include "asan_rtl.h"
#include "asan_int.h"

#include <sys/mman.h>

static void MmapNewPages(size_t n_pages) {
  void *res = mmap(0, kPageSize * n_pages,
                   PROT_READ | PROT_WRITE,
                   0, 0, 0);
  Printf("res "PP"\n");
}


void *__asan_memalign(size_t size, size_t alignment) {

}

void __asan_free(void *ptr) {

}
