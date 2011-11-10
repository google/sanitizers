extern "C" {
  void CFAllocatorDefaultDoubleFree();
  void CFAllocatorSystemDefaultDoubleFree();
  void CFAllocatorMallocDoubleFree();
  void CFAllocatorMallocZoneDoubleFree();
  void TestGCDRunBlock();
  void TestGCDReuseWqthreads();
}
