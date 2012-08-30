#include "sanitizer_common/sanitizer_allocator64.h"
#include "msan.h"

namespace __msan {

struct Metadata {
  uptr requested_size;
};

static const uptr kAllocatorSpace = 0x600000000000ULL;
static const uptr kAllocatorSize   = 0x80000000000;  // 8T.
static const uptr kMetadataSize  = sizeof(Metadata);

typedef SizeClassAllocator64<kAllocatorSpace, kAllocatorSize, kMetadataSize,
  DefaultSizeClassMap> PrimaryAllocator;
typedef SizeClassAllocatorLocalCache<PrimaryAllocator::kNumClasses,
  PrimaryAllocator> AllocatorCache;
typedef LargeMmapAllocator SecondaryAllocator;
typedef CombinedAllocator<PrimaryAllocator, AllocatorCache,
          SecondaryAllocator> Allocator;

static THREADLOCAL AllocatorCache cache;
static Allocator allocator;


static int inited = 0;

void Init() {
  if (inited) return;
  __msan_init();
  inited = true;  // this must happen before any threads are created.
  allocator.Init();
}

void *MsanAllocate(uptr size, uptr alignment, bool zeroise) {
  Init();
  void *res = allocator.Allocate(&cache, size, alignment, false);
  Metadata *meta = reinterpret_cast<Metadata*>(allocator.GetMetaData(res));
  meta->requested_size = size;
  if (zeroise)
    __msan_clear_and_unpoison(res, size);
  else if (flags.poison_in_malloc)
    __msan_poison(res, size);
  return res;
}

void MsanDeallocate(void *p) {
  Init();
  Metadata *meta = reinterpret_cast<Metadata*>(allocator.GetMetaData(p));
  uptr size = meta->requested_size;
  // This memory will not be reused by anyone else, so we are free to keep it
  // poisoned.
  __msan_poison(p, size);
  allocator.Deallocate(&cache, p);
}

void *MsanReallocate(StackTrace *stack, void *old_p, uptr new_size,
                     uptr alignment, bool zeroise) {
  if (msan_track_origins && msan_inited)
    Printf("MsanReallocate: stack.size = %zd\n", stack->size);

  if (!old_p)
    return MsanAllocate(new_size, alignment, zeroise);
  if (!new_size) {
    MsanDeallocate(old_p);
    return 0;
  }
  Metadata *meta = reinterpret_cast<Metadata*>(allocator.GetMetaData(old_p));
  uptr old_size = meta->requested_size;
  uptr actually_allocated_size = allocator.GetActuallyAllocatedSize(old_p);
  if (new_size <= actually_allocated_size) {
    // We are not reallocating here.
    meta->requested_size = new_size;
    if (new_size > old_size)
      __msan_poison((char*)old_p + old_size, new_size - old_size);
    return old_p;
  }
  uptr memcpy_size = Min(new_size, old_size);
  void *new_p = MsanAllocate(new_size, alignment, zeroise);
  // Printf("realloc: old_size %zd new_size %zd\n", old_size, new_size);
  if (new_p)
    __msan_memcpy_with_poison(new_p, old_p, memcpy_size);
  MsanDeallocate(old_p);
  return new_p;
}

}  // namespace __msan
