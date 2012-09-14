#include "msan.h"

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <unwind.h>
#include <execinfo.h>
#include <sys/time.h>
#include <sys/resource.h>


#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_procmaps.h"

namespace __msan {

static const uptr kMemBeg     = 0x600000000000;
static const uptr kMemEnd     = 0x7fffffffffff;
static const uptr kShadowBeg  = MEM_TO_SHADOW(kMemBeg);
static const uptr kShadowEnd  = MEM_TO_SHADOW(kMemEnd);
static const uptr kBad1Beg    = 0x100000000;  // 4G
static const uptr kBad1End    = kShadowBeg - 1;
static const uptr kBad2Beg    = kShadowEnd + 1;
static const uptr kBad2End    = kMemBeg - 1;
static const uptr kOriginsBeg = kBad2Beg;
static const uptr kOriginsEnd = kBad2End;

char *GetProcSelfMaps() {
  // FIXME
  static const int kSize = 1 << 22;
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

bool InitShadow(bool prot1, bool prot2, bool map_shadow, bool init_origins) {
  if (0) {
    Printf("__msan_init %p\n", &__msan_init);
    Printf("Memory   : %p %p\n", kMemBeg, kMemEnd);
    Printf("Bad2     : %p %p\n", kBad2Beg, kBad2End);
    Printf("Origins  : %p %p\n", kOriginsBeg, kOriginsEnd);
    Printf("Shadow   : %p %p\n", kShadowBeg, kShadowEnd);
    Printf("Bad1     : %p %p\n", kBad1Beg, kBad1End);
  }

  if (prot1 && !Mprotect(kBad1Beg, kBad1End - kBad1Beg))
    return false;
  if (prot2 && !Mprotect(kBad2Beg, kBad2End - kBad2Beg))
    return false;
  if (map_shadow) {
    void *shadow = MmapFixedNoReserve(kShadowBeg, kShadowEnd - kShadowBeg);
    if (shadow != (void*)kShadowBeg) return false;
  }
  if (init_origins) {
    void *origins = MmapFixedNoReserve(kOriginsBeg, kOriginsEnd - kOriginsBeg);
    if (origins != (void*)kOriginsBeg) return false;
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

// TODO: get rid of this once we are sure that the common unwinder is ok.
void PrintStack(uptr *addr, uptr size) {
  MemoryMappingLayout proc_maps;
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
  ucontext_t *ucontext = (ucontext_t*)context;
  uptr pc = ucontext->uc_mcontext.gregs[REG_RIP];
  uptr bp = ucontext->uc_mcontext.gregs[REG_RBP];
  PrintWarning(pc + 1 /*1 will be subtracted back in StackTrace::Print */, bp);
  ucontext->uc_mcontext.gregs[REG_RIP] += 2;
}

void InstallTrapHandler() {
  struct sigaction sigact;
  internal_memset(&sigact, 0, sizeof(sigact));
  sigact.sa_sigaction = MsanTrap;
  sigact.sa_flags = SA_SIGINFO;
  CHECK(0 == sigaction(SIGILL, &sigact, 0));
}

bool StackIsUnlimited() {
  struct rlimit rlim;
  CHECK_EQ(0, getrlimit(RLIMIT_STACK, &rlim));
  return (rlim.rlim_cur == (uptr)-1);
}

void SetSaneStackLimit() {
  struct rlimit rlim;
  rlim.rlim_max = 32 * 1024 * 1024;
  rlim.rlim_cur = 32 * 1024 * 1024;
  CHECK_EQ(0, setrlimit(RLIMIT_STACK, &rlim));
  CHECK(!StackIsUnlimited());
}

void ReExec() {
  static char *buff;
  uptr buff_size = 0;
  static const int kMaxArgv = 100;
  char *argv[kMaxArgv + 1];
  ReadFileToBuffer("/proc/self/cmdline", &buff, &buff_size, 1024 * 1024);
  argv[0] = buff;
  // Printf("argv[0]: %s\n", argv[0]);
  int argc, i;
  for (argc = 1, i = 1; ; i++) {
    if (buff[i] == 0) {
      if (buff[i+1] == 0) break;
      argv[argc] = &buff[i+1];
      // Printf("argv[%d]: %s\n", i, argv[argc]);
      CHECK_LE(argc, kMaxArgv);  // FIXME: make this more flexible.
      argc++;
    }
  }
  argv[argc] = 0;
  execv(argv[0], argv);
}

void MsanDie() {
  _exit(flags.exit_code);
}

}
