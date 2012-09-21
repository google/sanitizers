#ifndef MSAN_PLATFORM_LIMITS_H
#define MSAN_PLATFORM_LIMITS_H

namespace __msan {
  extern unsigned struct_utsname_sz;
  extern unsigned struct_stat_sz;
  extern unsigned struct_stat64_sz;
  extern unsigned struct_rlimit_sz;
  extern unsigned struct_rlimit64_sz;
  extern unsigned struct_dirent_sz;
};

#endif
