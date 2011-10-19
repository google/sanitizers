#!/usr/bin/env python
import os
import re
import sys
import string
import subprocess

pipes = {}

# TODO(glider): need some refactoring here
def symbolize_addr2line(line):
  #0 0x7f6e35cf2e45  (/blah/foo.so+0x11fe45)
  match = re.match('^( *#[0-9]+ *0x[0-9a-f]+) *\((.*)\+(0x[0-9a-f]+)\)', line)
  if match:
    binary = match.group(2)
    addr = match.group(3)
    if not pipes.has_key(binary):
      pipes[binary] = subprocess.Popen(["addr2line", "-f", "-e", binary],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    p = pipes[binary]
    try:
      print >>p.stdin, addr
      function_name = p.stdout.readline().rstrip()
      file_name     = p.stdout.readline().rstrip()
    except:
      function_name = ""
      file_name = ""
    for path_to_cut in sys.argv[1:]:
      file_name = re.sub(".*" + path_to_cut, "", file_name)
    file_name = re.sub(".*asan_[a-z_]*.cc:[0-9]*", "_asan_rtl_", file_name)
    file_name = re.sub(".*crtstuff.c:0", "???:0", file_name)

    print match.group(1), "in", function_name, file_name
  else:
    print line.rstrip()

def symbolize_atos(line):
  #0 0x7f6e35cf2e45  (/blah/foo.so+0x11fe45)
  match = re.match('^( *#[0-9]+ *)(0x[0-9a-f]+) *\((.*)\+(0x[0-9a-f]+)\)', line)
  if match:
    #print line
    prefix = match.group(1)
    addr = match.group(2)
    binary = match.group(3)
    offset = match.group(4)
    load_addr = int(addr, 16) - int(offset, 16)
    if not pipes.has_key(binary):
      #print "atos -o %s -l %s" % (binary, hex(load_addr))
      pipes[binary] = subprocess.Popen(["atos", "-o", binary],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE,)
    p = pipes[binary]
    # TODO(glider): how to tell if the address is absolute?
    if ".app/" in binary and not ".framework" in binary:
      print >>p.stdin, "%s" % addr
    else:
      print >>p.stdin, "%s" % offset
    # TODO(glider): it's more efficient to make a batch atos run for each binary.
    p.stdin.close()
    atos_line = p.stdout.readline().rstrip()
    del pipes[binary]

    print "%s%s in %s" % (prefix, addr, atos_line)
  else:
    print line.rstrip()

system = os.uname()[0]
if system in ['Linux', 'Darwin']:
  for line in sys.stdin:
    if system == 'Linux':
      symbolize_addr2line(line)
    elif system == 'Darwin':
      symbolize_atos(line)
else:
  print 'Unknown system: ', system
