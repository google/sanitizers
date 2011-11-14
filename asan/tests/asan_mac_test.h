extern "C" {
  void CFAllocatorDefaultDoubleFree();
  void CFAllocatorSystemDefaultDoubleFree();
  void CFAllocatorMallocDoubleFree();
  void CFAllocatorMallocZoneDoubleFree();
  void CallFreeOnWorkqueue(void *mem);
  void TestGCDRunBlock();
  void TestGCDReuseWqthreads();
  void TestGCDDispatchAfter();
  void TestGCDInTSDDestructor();
}
