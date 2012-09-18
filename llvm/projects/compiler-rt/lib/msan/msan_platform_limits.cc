#include "msan_platform_limits.h"

#include <sys/utsname.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/resource.h>

namespace __msan {
  unsigned struct_utsname_sz = sizeof(struct utsname);
  unsigned struct_stat_sz = sizeof(struct stat);
  unsigned struct_stat64_sz = sizeof(struct stat64);
  unsigned struct_rlimit_sz = sizeof(struct rlimit);
  unsigned struct_rlimit64_sz = sizeof(struct rlimit64);
};
