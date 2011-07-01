#!/usr/bin/python2.4
import re
import sys
import string
import subprocess

atos_pipes = {}

for line in sys.stdin:
  #0 0x7f6e35cf2e45  (/blah/foo.so+0x11fe45)
  match = re.match('^( *#[0-9]+ *)(0x[0-9a-f]+) *\((.*)\+(0x[0-9a-f]+)\)', line)
  if match:
    #print line
    prefix = match.group(1)
    addr = match.group(2)
    binary = match.group(3)
    offset = match.group(4)
    load_addr = int(addr, 16) - int(offset, 16)
    if not atos_pipes.has_key(binary):
      #print "atos -o %s -l %s" % (binary, hex(load_addr))
      atos_pipes[binary] = subprocess.Popen(["atos", "-o", binary],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE,)
    p = atos_pipes[binary]
    if ".app/" in binary and not ".framework" in binary:
      print >>p.stdin, "%s" % addr
    else:
      print >>p.stdin, "%s" % offset
    # TODO(glider): it's more efficient to make a batch atos run for each binary.
    p.stdin.close()
    atos_line = p.stdout.readline().rstrip()
    del atos_pipes[binary]

    print "%s%s in %s" % (prefix, addr, atos_line)
  else:
    print line.rstrip()
