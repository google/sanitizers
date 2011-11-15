extern "C" {
  void CFAllocatorDefaultDoubleFree();
  void CFAllocatorSystemDefaultDoubleFree();
  void CFAllocatorMallocDoubleFree();
  void CFAllocatorMallocZoneDoubleFree();
  void CallFreeOnWorkqueue(void *mem);
  void TestGCDDispatchAsync();
  void TestGCDDispatchSync();
  void TestGCDReuseWqthreadsAsync();
  void TestGCDReuseWqthreadsSync();
  void TestGCDDispatchAfter();
  void TestGCDInTSDDestructor();
}
