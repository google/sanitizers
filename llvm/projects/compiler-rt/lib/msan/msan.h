#ifndef MSAN_H
#define MSAN_H

#include "sanitizer_common/sanitizer_internal_defs.h"
#include "msan_interface.h"

#define MEM_TO_SHADOW(mem) ((mem) & ~0x400000000000ULL)

namespace __msan {
uptr ReadFromFile(const char *path, char *buff, uptr size);
bool ProtectRange(uptr beg, uptr end);
void *Mmap(void *addr, uptr length, int prot, int flags,
                    int fd, u64 offset);
void CatProcSelfMaps();
bool InitShadow(bool prot1, bool prot2, bool map_shadow);
char *GetProcSelfMaps();
void InitializeInterceptors();

void *MsanReallocate(void *oldp, uptr size,
                     uptr alignment, bool zeroise);
void MsanDeallocate(void *ptr);
void GdbBackTrace();  // FIXME
void InstallSIGILLHandler();

extern int msan_inited;

}

#endif  // MSAN_H
