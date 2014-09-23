#!/usr/bin/env python
import os
import re
import sys

blacklist=["rtld", "/dl-", "elf/", "string/mem", "time/time",
           "time/gettimeofday", "time/timegm", "time/timespec_get",
           "nptl/libc_pthread_init", "nptl/register-atfork", "string/strstr"]
#whitelist=[
#  "csu/", "iconv/", "locale/", "assert/", "ctype/",
#  "intl/", "catgets/", "math/", "setjmp/", "signal/",
#  "stdlib/", "stdio-common/", "libio/", "malloc/",
#  "string/", "wcsmbs/", "time/", "dirent/", "grp/", "pwd/", "posix/",
#  "io/", "termios/", "resource/", "misc/", "socket/", "sysvipc/", "gmon/",
#  "wctype/", "shadow/", "gshadow/", "argp/", "nptl/", "debug/", "inet/",
#  "resolv/", "nss/", "sunrpc/", "nis/", "nscd/", "streams/", "login/"]

def AllowAsan(obj):
  for b in blacklist:
    if re.search(b, obj): return False
#  for b in whitelist:
#    if re.search(b, obj): return True
  return True

if __name__ == '__main__':
  last_was_minus_o = False
  asan_ok = False;
  GCC = "gcc"
  res = [GCC]
  for a in sys.argv[1:]:
    if not re.match(r"-Wl,-z,defs", a):
      res.append(a)
    # print last_was_minus_o, a
    if last_was_minus_o:
      m = re.match(r"/.*build/(.*).os", a)
      if m:
        obj = m.group(1)
        if AllowAsan(obj):
          asan_ok = True;
    last_was_minus_o = a == "-o"
  if asan_ok:
    print >> sys.stderr, "ASAN:", a
    res.append("-fsanitize=address") 
  # print res
  os.execvp(GCC, res)
