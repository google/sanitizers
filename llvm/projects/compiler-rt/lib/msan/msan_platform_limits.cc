#include "msan_platform_limits.h"

#include <sys/utsname.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/vfs.h>
#include <dirent.h>


namespace __msan {
  unsigned struct_utsname_sz = sizeof(struct utsname);
  unsigned struct_stat_sz = sizeof(struct stat);
  unsigned struct_stat64_sz = sizeof(struct stat64);
  unsigned struct_rlimit_sz = sizeof(struct rlimit);
  unsigned struct_rlimit64_sz = sizeof(struct rlimit64);
  unsigned struct_dirent_sz = sizeof(struct dirent);
  unsigned struct_statfs_sz = sizeof(struct statfs);
  unsigned struct_statfs64_sz = sizeof(struct statfs64);
};
