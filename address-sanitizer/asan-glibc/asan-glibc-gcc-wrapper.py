#!/usr/bin/env python
from __future__ import print_function

import os
import re
import shutil
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
           'string/wordcopy',  # Same.
           ]

def AllowAsan(out_file):
  match = re.match(r'/.*build/(.*).os$', out_file)
  if not match:
    #print >>sys.stderr, 'FALLBACK_NO_MATCH: %s' % out_file
    return False
  obj = match.group(1)

  for b in blacklist:
    if re.search(b, obj):
      #print >>sys.stderr, 'FALLBACK_BLACKLIST: %s' % obj
      return False
  return True

def o():
  try:
    i = sys.argv.index('-o')
    return sys.argv[i + 1]
  except Exception:
    return ''

#def skip(obj):
#  return False
#  # Do not build executables. Workaround for
#  # https://gcc.gnu.org/bugzilla/show_bug.cgi?id=65639
#  skip_list = [
#    'iconv/iconvconfig',
#    'iconv/iconv_prog',
#    'sunrpc/rpcgen',
#    'sunrpc/cross-rpcgen',
#    'debug/xtrace',
#    'debug/pcprofiledump',
#    'debug/catchsegv',
#    'catgets/gencat',
#    'nss/makedb',
#    'nss/getent',
#    'malloc/mtrace',
#    'timezone/tzselect',
#    'timezone/zdump',
#    'timezone/zic',
#    'posix/getconf',
#    'locale/locale',
#    'locale/localedef',
#    'nscd/nscd',
#    'config.status',
#    'testrun.sh',
#    'io/pwd',
#    'elf/ldd',
#    'elf/pldd',
#    'elf/sprof',
#    'elf/ldconfig',
#    'elf/sln',
#    'login/utmpdump'
#  ]
#  for name in skip_list:
#    if obj.endswith(name):
#      asan_build = os.getenv('ASAN_BUILD')
#      assert(asan_build)
#      plain_build = os.getenv('PLAIN_BUILD')
#      assert(plain_build)
#      shutil.copy2(plain_build + '/' + name, asan_build + '/' + name)
#      return True
#  return False

if __name__ == '__main__':
#Uncomment this if you want to run "make install" (instead of doing a
#libraries-only build).
#  if skip(o()):
#    print >>sys.stderr, "SKIPPING:", o()
#    sys.exit(0)

  args = sys.argv[1:]
  args = [arg for arg in args if arg != '-Wl,-z,defs']

  if AllowAsan(o()):
    print('ASAN:', o(), file=sys.stderr)
    args.append('-fsanitize=address')
    # Temporarily disable UAR. See comment asan-init-stub.c
    args.append('--param')
    args.append('asan-use-after-return=0')

  if re.search(r'.so(|.\d)$', o()):
    print("ADDING STUB:", o(), file=sys.stderr)
    args.append(ASAN_INIT_STUB)

  args.append('-fno-omit-frame-pointer')

  os.execvp(GCC, [GCC] + args)
