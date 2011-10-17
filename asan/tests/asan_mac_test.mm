#import <stdio.h>
#import <string.h>

#import <CoreFoundation/CFBase.h>
#import <Foundation/NSObject.h>

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


// Test the +load instrumentation.
// Because the +load methods are invoked before anything else is initialized,
// it makes little sense to wrap the code below into a gTest test case.
// If AddressSanitizer doesn't instrument the +load method below correctly,
// everything will just crash.

char kStartupStr[] =
    "If you see this message, AddressSanitizer is instrumenting "
    "the +load methods correctly.";

@interface LoadSomething : NSObject {
}
@end

@implementation LoadSomething

+(void) load {
  for (int i = 0; i < strlen(kStartupStr); i++) {
    volatile char ch = kStartupStr[i];  // make sure no optimizations occur.
    fprintf(stderr, "%c", ch);
  }
  fprintf(stderr, "\n");
}

@end
