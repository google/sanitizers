#import <CoreFoundation/CFBase.h>

void CFAllocatorDefaultDoubleFree() {
  void *mem =  CFAllocatorAllocate(kCFAllocatorDefault, 5, 0);
  CFAllocatorDeallocate(kCFAllocatorDefault, mem);
  CFAllocatorDeallocate(kCFAllocatorDefault, mem);
}

void CFAllocatorSystemDefaultDoubleFree() {
  void *mem =  CFAllocatorAllocate(kCFAllocatorSystemDefault, 5, 0);
  CFAllocatorDeallocate(kCFAllocatorSystemDefault, mem);
  CFAllocatorDeallocate(kCFAllocatorSystemDefault, mem);
}

void CFAllocatorMallocDoubleFree() {
  void *mem =  CFAllocatorAllocate(kCFAllocatorMalloc, 5, 0);
  CFAllocatorDeallocate(kCFAllocatorMalloc, mem);
  CFAllocatorDeallocate(kCFAllocatorMalloc, mem);
}

void CFAllocatorMallocZoneDoubleFree() {
  void *mem =  CFAllocatorAllocate(kCFAllocatorMallocZone, 5, 0);
  CFAllocatorDeallocate(kCFAllocatorMallocZone, mem);
  CFAllocatorDeallocate(kCFAllocatorMallocZone, mem);
}
