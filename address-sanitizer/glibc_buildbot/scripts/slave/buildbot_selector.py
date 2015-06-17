#!/usr/bin/python

import os
import subprocess
import sys

THIS_DIR=os.path.dirname(sys.argv[0])


def bash(script, args=[]):
    return ['bash', os.path.join(THIS_DIR, script)] + args

BOT_ASSIGNMENT = {
    'glibc-x86_64-linux': bash('glibc-native.sh'),
    'glibc-i686-linux': bash('glibc-native.sh', [
        '--build=i686-linux',
        'CC=gcc -m32',
        'CXX=g++ -m32',
    ]),
    'glibc-power8-linux': bash('glibc-native.sh', [
        '--with-cpu=power8',
        '--enable-lock-elision',
    ])
}

BOT_ADDITIONAL_ENV = {
}

def Main():
  builder = os.environ.get('BUILDBOT_BUILDERNAME')
  print "builder name: %s" % (builder)
  cmd = BOT_ASSIGNMENT.get(builder)
  if not cmd:
    sys.stderr.write('ERROR - unset/invalid builder name\n')
    sys.exit(1)

  print "%s runs: %r\n" % (builder, cmd)
  sys.stdout.flush()

  bot_env = os.environ
  bot_env.update(BOT_ADDITIONAL_ENV.get(builder, {}))
  if 'TMPDIR' in bot_env:
    del bot_env['TMPDIR']

  retcode = subprocess.call(cmd, env=bot_env)
  sys.exit(retcode)


if __name__ == '__main__':
  Main()
