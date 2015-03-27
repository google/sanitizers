#!/usr/bin/env python
import os
import re
import sys

blacklist=["rtld", "/dl-", "elf/", "string/mem", "time/time",
           "time/gettimeofday", "time/timegm", "time/timespec_get",
           "nptl/libc_pthread_init", "nptl/register-atfork", "string/strstr",
           "string/strcasestr",
#0 0x7f5147637bd9 in _mm_load_si128 .../x86_64-unknown-linux-gnu/5.0.0/include/emmintrin.h:688
#1 0x7f5147637bd9 in __strcspn_sse42 .../glibc-2.19/string/../sysdeps/x86_64/multiarch/strcspn-c.c:123
           "string/strcspn-c",  # May read 16-aligned data outside of buffer.
           "string/strpbrk-c",  # Same function as strcspn
           "string/strspn-c",  # Same.
           ]

def AllowAsan(obj):
  for b in blacklist:
    if re.search(b, obj): return False
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
    # Temporarily disable UAR. See comment asan-init-stub.c
    res.append("--param")
    res.append("asan-use-after-return=0")
  if "libc.so.6" in ' '.join(res):
    res.append(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            'asan-init-stub.o'))
  os.execvp(GCC, res)
