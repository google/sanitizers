#!/usr/bin/env python
import os
import re
import sys

ASAN_INIT_STUB=os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            'asan-init-stub.o')
GCC = 'gcc'

blacklist=['rtld', '/dl-', 'elf/', 'string/mem', 'time/time',
           'time/gettimeofday', 'time/timegm', 'time/timespec_get',
           'nptl/libc_pthread_init', 'nptl/register-atfork', 'string/strstr',
           'string/strcasestr',
#0 0x7f5147637bd9 in _mm_load_si128 .../x86_64-unknown-linux-gnu/5.0.0/include/emmintrin.h:688
#1 0x7f5147637bd9 in __strcspn_sse42 .../glibc-2.19/string/../sysdeps/x86_64/multiarch/strcspn-c.c:123
           'string/strcspn-c',  # May read 16-aligned data outside of buffer.
           'string/strpbrk-c',  # Same function as strcspn
           'string/strspn-c',  # Same.
           ]

def AllowAsan(obj):
  for b in blacklist:
    if re.search(b, obj): return False
  return True

def o():
  try:
    i = sys.argv.index('-o')
    return sys.argv[i + 1]
  except Exception:
    return ''

if __name__ == '__main__':
  args = sys.argv[1:]
  args = [arg for arg in args if arg != '-Wl,-z,defs']
  asan_ok = re.match(r'/.*build/(.*).os', o()) and AllowAsan(o())

  if asan_ok:
    print >> sys.stderr, 'ASAN:', o()
    args.append('-fsanitize=address')
    # Temporarily disable UAR. See comment asan-init-stub.c
    args.append('--param')
    args.append('asan-use-after-return=0')
    if '-c' not in args and '-S' not in args and '-E' not in args:
      args.append(ASAN_INIT_STUB)

  args.append('-fno-omit-frame-pointer')

  os.execvp(GCC, [GCC] + args)
