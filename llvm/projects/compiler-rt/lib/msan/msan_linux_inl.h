#include "msan.h"

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <unwind.h>
#include <execinfo.h>

#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_procmaps.h"

namespace __msan {

static const uptr kMemBeg     = 0x7f0000000000;
static const uptr kMemEnd     = 0x7fffffffffff;
static const uptr kShadowBeg  = MEM_TO_SHADOW(kMemBeg);
static const uptr kShadowEnd  = MEM_TO_SHADOW(kMemEnd);
static const uptr kBad1Beg    = 0x100000000;  // 4G
static const uptr kBad1End    = kShadowBeg - 1;
static const uptr kBad2Beg    = kShadowEnd + 1;
static const uptr kBad2End    = kMemBeg - 1;

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
  int fd = internal_open(path, false);
  if (fd < 0) return 0;
  uptr res = internal_read(fd, buff, size);
  internal_close(fd);
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

  if (prot1 && !Mprotect(kBad1Beg, kBad1End - kBad1Beg))
    return false;
  if (prot2 && !Mprotect(kBad2Beg, kBad2End - kBad2Beg))
    return false;
  if (map_shadow) {
    void *shadow = MmapFixedNoReserve(kShadowBeg, kShadowEnd - kShadowBeg);
    return shadow == (void*)kShadowBeg;
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

// TODO: move ASan stacktrace-related code to sanitizer_common and reuse it here
void PrintStack(uptr *addr, uptr size) {
  ProcessMaps proc_maps;
  uptr frame_num = 0;
  for (uptr i = 0; i < size && addr[i]; i++) {
    uptr pc = addr[i];
    uptr offset;
    char filename[4096];
    if (proc_maps.GetObjectNameAndOffset(pc, &offset,
            filename, sizeof(filename))) {
      Printf("    #%zu 0x%zx (%s+0x%zx)\n", frame_num, pc, filename,
          offset);
    } else {
      Printf("    #%zu 0x%zx\n", frame_num, pc);
    }
    frame_num++;
  }
}

void BacktraceStackTrace() {
  uptr buffer[50];
  int res = backtrace((void**)buffer, 50);
  PrintStack(buffer, 50);
}

static void MsanTrap(int, siginfo_t *siginfo, void *context) {
  __msan_warning();
  ucontext_t *ucontext = (ucontext_t*)context;
  ucontext->uc_mcontext.gregs[REG_RIP] += 2;
}

void InstallTrapHandler() {
  struct sigaction sigact;
  internal_memset(&sigact, 0, sizeof(sigact));
  sigact.sa_sigaction = MsanTrap;
  sigact.sa_flags = SA_SIGINFO;
  CHECK(0 == sigaction(SIGILL, &sigact, 0));
}

}

namespace __sanitizer {
void Die() {
  _exit(__msan::flags.exit_code);
}

void CheckFailed(const char *file, int line, const char *cond, u64 v1, u64 v2) {
  Printf("MemorySanitizer CHECK failed: %s:%d \"%s\" (%zx, %zx)\n",
             file, line, cond, (uptr)v1, (uptr)v2);
  Die();
}
}  // namespace
