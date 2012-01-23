#!/usr/bin/python

import os
import subprocess
import sys

THIS_DIR=os.path.dirname(sys.argv[0])


def bash(path):
    return 'bash ' + os.path.join(THIS_DIR, path)

BOT_ASSIGNMENT = {
    'buildbot-full': bash('buildbot_standard.sh'),
}

def Main():
  builder = os.environ.get('BUILDBOT_BUILDERNAME')
  cmd = BOT_ASSIGNMENT.get(builder)
  if not cmd:
    sys.stderr.write('ERROR - unset/invalid builder name\n')
    sys.exit(1)

  print "%s runs: %s\n" % (builder, cmd)
  sys.stdout.flush()

  retcode = subprocess.call(cmd, env=os.environ, shell=True)
  sys.exit(retcode)


if __name__ == '__main__':
  Main()
