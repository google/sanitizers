#ifndef MSAN_H
#define MSAN_H

#include "sanitizer_common/sanitizer_internal_defs.h"
#include "sanitizer_common/sanitizer_stacktrace.h"
#include "msan_interface.h"

#define MEM_TO_SHADOW(mem) ((mem) & ~0x400000000000ULL)

namespace __msan {
extern int msan_inited;
extern bool msan_init_is_running;
extern bool msan_track_origins;

uptr ReadFromFile(const char *path, char *buff, uptr size);
bool ProtectRange(uptr beg, uptr end);
void CatProcSelfMaps();
bool InitShadow(bool prot1, bool prot2, bool map_shadow, bool init_origins);
char *GetProcSelfMaps();
void InitializeInterceptors();

void *MsanReallocate(StackTrace *stack, void *oldp, uptr size,
                     uptr alignment, bool zeroise);
void MsanDeallocate(void *ptr);
void GdbBackTrace();  // FIXME
void BacktraceStackTrace();
void InstallTrapHandler();
void ReplaceOperatorsNewAndDelete();

// Flags.
struct Flags {
  bool poison_with_zeroes;  // default: false
  bool poison_in_malloc;  // default: true
  int  exit_code;
  bool fast_unwinder;
  int  num_callers;
};

extern Flags flags;

void GetStackTrace(StackTrace *stack, uptr max_s, uptr pc, uptr bp);

#define GET_MALLOC_STACK_TRACE                                     \
  StackTrace stack;                                                \
  stack.size = 0;                                                  \
  if (msan_track_origins && msan_inited)                           \
    GetStackTrace(&stack, flags.num_callers,                       \
      StackTrace::GetCurrentPc(), GET_CURRENT_FRAME())

}  // namespace __msan

#endif  // MSAN_H
