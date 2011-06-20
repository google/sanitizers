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
#include <stdint.h>
#include <algorithm>

namespace {

static const size_t kRedzone      = kMinRedzone * 2;
static const size_t kMinAllocSize = kRedzone * 2;
static const size_t kMinMmapSize  = kPageSize * 128;

static inline bool IsPowerOfTwo(size_t x) {
  return (x & (x - 1)) == 0;
}

static inline size_t Log2(size_t x) {
  CHECK(IsPowerOfTwo(x));
  return __builtin_ctzl(x);
}

static inline size_t RoundUptoRedzone(size_t size) {
  return ((size + kRedzone - 1) / kRedzone) * kRedzone;
}

static inline size_t RoundUptoPowerOfTwo(size_t size) {
  CHECK(size);
  if (IsPowerOfTwo(size)) return size;
  size_t up = __WORDSIZE - __builtin_clzl(size);
  CHECK(size < (1UL << up));
  CHECK(size > (1UL << (up - 1)));
  return 1UL << up;
}

static uint8_t *MmapNewPages(size_t size) {
  CHECK((size % kPageSize) == 0);
  uint8_t *res = (uint8_t*)mmap(0, size,
                   PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANON, -1, 0);
  if (res == (uint8_t*)-1) {
    Printf("failed to mmap %ld bytes\n", size);
    abort();
  }
  return res;
}

// Every chunk of memory allocated by this allocator can be in one of 3 states:
// CHUNK_AVAILABLE: the chunk is in the free list and ready to be allocated.
// CHUNK_ALLOCATED: the chunk is allocated and not yet freed.
// CHUNK_QUARANTINE: the chunk was freed and put into quarantine zone.
//
// The pseudo state CHUNK_MEMALIGN is used to mark that the address is not 
// the beginning of a Chunk (in which case the next work contains the address
// of the Chunk).
//
// The magic numbers for the enum values are taken randomly.
enum {
  CHUNK_AVAILABLE  = 0x573B5CE5,
  CHUNK_ALLOCATED  = 0x32041A36,
  CHUNK_QUARANTINE = 0x1978BAE3,
  CHUNK_MEMALIGN   = 0xDC68ECD8,
};

struct Chunk {
  uintptr_t    chunk_state;     // Should be the first field.
  size_t       allocated_size;  // Must be power of two
  size_t       used_size;
  Chunk       *next;
  Chunk       *prev;
};

class FreeList {
 public:
  Chunk *AllocateChunk(size_t size) {
    CHECK(IsPowerOfTwo(size));
    size_t idx = Log2(size);
    if (!chunks[idx]) {
      GetNewChunks(size); 
    }
    Chunk *res = chunks[idx];
    CHECK(res);
    chunks[idx] = res->next;
    res->next = res->prev = 0;
    CHECK(res->chunk_state == CHUNK_AVAILABLE);
    res->chunk_state = CHUNK_ALLOCATED;
    return res;
  }

  void TakeChunkBack(Chunk *chunk) {
    CHECK(chunk);
    CHECK(chunk->chunk_state == CHUNK_QUARANTINE);
    CHECK(IsPowerOfTwo(chunk->allocated_size));
    size_t idx = Log2(chunk->allocated_size);
    chunk->next = chunks[idx];
    chunk->chunk_state = CHUNK_AVAILABLE;
    chunks[idx] = chunk;
  }

  void GetNewChunks(size_t size) {
    size_t idx = Log2(size);
    CHECK(chunks[idx] == NULL);
    CHECK(IsPowerOfTwo(size));
    CHECK(IsPowerOfTwo(kMinMmapSize));
    size_t mmap_size = std::max(size, kMinMmapSize);
    CHECK(IsPowerOfTwo(mmap_size));
    uint8_t *mem = MmapNewPages(mmap_size);
    for (size_t i = 0; i < mmap_size / size; i++) {
      Chunk *chunk = (Chunk*)(mem + i * size);
      chunk->chunk_state = CHUNK_AVAILABLE;
      chunk->allocated_size = size;
      chunk->next = chunks[idx];
      chunks[idx] = chunk;
    }
  }

 private:
  Chunk *chunks[__WORDSIZE];
};

static FreeList g_free_list;

struct Quarantine {
  size_t total_size;
  Chunk *first;

  void Put(Chunk *chunk) {
    CHECK(chunk);
    CHECK(chunk->chunk_state == CHUNK_ALLOCATED);
    chunk->chunk_state = CHUNK_QUARANTINE;
    g_free_list.TakeChunkBack(chunk);
  }
};

static Quarantine g_quarantine;

static uint8_t *Allocate(size_t size, size_t alignment) {
  // Printf("Allocate %ld %ld\n", size, alignment);
  CHECK(IsPowerOfTwo(alignment));
  size_t rounded_size = RoundUptoRedzone(size);
  if (alignment > kRedzone) {
    rounded_size += alignment;
  }
  size_t needed_size = rounded_size + kRedzone;
  CHECK((needed_size % kRedzone) == 0);
  size_t size_to_allocate = RoundUptoPowerOfTwo(needed_size);
  CHECK(size_to_allocate >= kMinAllocSize);
  CHECK((size_to_allocate % kRedzone) == 0);

  Chunk *chunk = g_free_list.AllocateChunk(size_to_allocate);
  CHECK(chunk);
  CHECK(chunk->allocated_size == size_to_allocate);
  CHECK(chunk->chunk_state == CHUNK_ALLOCATED);
  chunk->used_size = size;
  uintptr_t addr = (uintptr_t)chunk + kRedzone;

  if (alignment > kRedzone && (addr & (alignment - 1))) {
    size_t alignment_log = Log2(alignment);
    // Printf("xx1 "PP"\n", addr);
    addr = ((addr + alignment - 1) >> alignment_log) << alignment_log;
    CHECK((addr & (alignment - 1)) == 0);
    uintptr_t *p = (uintptr_t*)(addr - kRedzone);
    p[0] = CHUNK_MEMALIGN;
    p[1] = (uintptr_t)chunk;
  }
  // Printf("ret "PP"\n", addr);
  return (uint8_t*)addr;
}

static void Deallocate(uint8_t *ptr) {
  if (!ptr) return;
  // Printf("dl0 "PP"\n", ptr);
  Chunk *chunk = (Chunk*)(ptr - kRedzone);
  // Printf("dl1 "PP"\n", chunk);
  if (chunk->chunk_state == CHUNK_MEMALIGN) {
    chunk = (Chunk*)((uintptr_t*)chunk)[1];
    // Printf("dl2 "PP"\n", chunk);
  }
  CHECK(chunk->chunk_state == CHUNK_ALLOCATED);
  g_quarantine.Put(chunk);
}

}  // namespace

void *__asan_memalign(size_t size, size_t alignment) {
  return (void*)Allocate(size, alignment);
}

void __asan_free(void *ptr) {
  Deallocate((uint8_t*)ptr);
}
