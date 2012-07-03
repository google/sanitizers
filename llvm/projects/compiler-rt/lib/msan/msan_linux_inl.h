#include "msan.h"

#include <sys/time.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <unwind.h>

namespace __msan {

static const uptr kMemBeg     = 0x7f0000000000;
static const uptr kMemEnd     = 0x7fffffffffff;
static const uptr kShadowBeg  = MEM_TO_SHADOW(kMemBeg);
static const uptr kShadowEnd  = MEM_TO_SHADOW(kMemEnd);
static const uptr kBad1Beg    = 0x200000;
static const uptr kBad1End    = kShadowBeg - 1;
static const uptr kBad2Beg    = kShadowEnd + 1;
static const uptr kBad2End    = kMemBeg - 1;

void *Mmap(void *addr, uptr length, int prot, int flags,
                    int fd, u64 offset) {
# if __WORDSIZE == 64
  return (void *)syscall(__NR_mmap, addr, length, prot, flags, fd, offset);
# else
  return (void *)syscall(__NR_mmap2, addr, length, prot, flags, fd, offset);
# endif
}

static int MsanOpenReadonly(const char* filename) {
    return syscall(__NR_open, filename, O_RDONLY);
}

static uptr MsanRead(int fd, void *buf, uptr count) {
    return (uptr)syscall(__NR_read, fd, buf, count);
}

static int MsanClose(int fd) {
    return syscall(__NR_close, fd);
}


bool ProtectRange(uptr beg, uptr end) {
  return  beg == (uptr)Mmap((void*)(beg), end - beg,
      PROT_NONE,
      MAP_PRIVATE | MAP_ANON | MAP_FIXED | MAP_NORESERVE,
      -1, 0);
}

char *GetProcSelfMaps() {
  // FIXME
  static const int kSize = 1 << 20;
  static char maps[kSize];
  size_t s = ReadFromFile("/proc/self/maps", maps, kSize - 1);
  maps[s] = 0;
  return maps;
}

void CatProcSelfMaps() {
  Printf("%s", GetProcSelfMaps());
}

uptr ReadFromFile(const char *path, char *buff, uptr size) {
  int fd = MsanOpenReadonly(path);
  if (fd < 0) return 0;
  uptr res = MsanRead(fd, buff, size);
  MsanClose(fd);
  return res;
}

bool InitShadow(bool prot1, bool prot2, bool map_shadow) {
  if (0) {
    Printf("__msan_init %p\n", &__msan_init);
    Printf("Memory: %12lx %12lx\n", kMemBeg, kMemEnd);
    Printf("Bad2  : %12lx %12lx\n", kBad2Beg, kBad2End);
    Printf("Shadow: %12lx %12lx\n", kShadowBeg, kShadowEnd);
    Printf("Bad1  : %12lx %12lx\n", kBad1Beg, kBad1End);
  }

  if (prot1 && !ProtectRange(kBad1Beg, kBad1End))
    return false;
  if (prot2 && !ProtectRange(kBad2Beg, kBad2End))
    return false;
  if (map_shadow) {
    uptr shadow = (uptr)Mmap((void*)kShadowBeg,
                             kShadowEnd - kShadowBeg,
                             PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANON |
                             MAP_FIXED | MAP_NORESERVE,
                             0, 0);
    return shadow == kShadowBeg;
  }
  return true;
}

void GdbBackTrace() {
  char cmd[100];
  sprintf(cmd, "gdb -q --batch -ex bt /proc/%d/exe %d "
          "> /dev/stderr",
          GetPid(), GetPid());
  system(cmd);
}

}

namespace __sanitizer {
void Die() {
  _exit(msan_exit_code);
}

void CheckFailed(const char *file, int line, const char *cond, u64 v1, u64 v2) {
  Printf("MemorySanitizer CHECK failed: %s:%d \"%s\" (%zx, %zx)\n",
             file, line, cond, (uptr)v1, (uptr)v2);
  Die();
}
}  // namespace
