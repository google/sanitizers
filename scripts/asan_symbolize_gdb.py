#!/usr/bin/python2.4
import re
import sys
import string
import subprocess

gdb_pipes = {}

for line in sys.stdin:
  #0 0x7f6e35cf2e45  (/blah/foo.so+0x11fe45)
  match = re.match('^( *#[0-9]+ *)(0x[0-9a-f]+) *\((.*)\+(0x[0-9a-f]+)\)', line)
  if match:
    prefix = match.group(1)
    addr = match.group(2)
    binary = match.group(3)
    offset = match.group(4)
    if not gdb_pipes.has_key(binary):
      gdb_pipes[binary] = subprocess.Popen(["gdb", "-q", "-s", binary ],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE,)
    p = gdb_pipes[binary]
    file_name = ""
    line_no = ""
    function_name = ""
    if ".app" in binary:
      offset = addr
    print >>p.stdin, "info symbol %s" % offset
    gdb_line = p.stdout.readline().rstrip()
    gdb_line = re.sub("^\(gdb\) ", "", gdb_line)
    chunks = gdb_line.split(" in section ")
    if len(chunks) > 1:
      function_name = chunks[0]
      function_name = re.sub("\+ [0-9]*", "", function_name)
    print >>p.stdin, "info line *%s" % offset
    gdb_line = p.stdout.readline().rstrip()
    gdb_line = re.sub("^\(gdb\) ", "", gdb_line)
    chunks = gdb_line.split(" starts at address ")
    if len(chunks) > 1:
      match = re.match('^Line ([0-9]*) of "([^"]*)"', chunks[0])
      if match:
        line_no = match.group(1)
        file_name = match.group(2)
    for path_to_cut in sys.argv[1:]:
      file_name = re.sub(".*" + path_to_cut, "", file_name)
    file_name = re.sub(".*asan_rtl.cc:[0-9]*", "_asan_rtl_", file_name)
    file_name = re.sub(".*crtstuff.c:0", "???:0", file_name)

    if file_name:
      print "%s%s in %s %s:%s" % (prefix, addr, function_name, file_name, line_no)
    else:
      print "%s%s in %s" % (prefix, addr, function_name)
    print line
  else:
    print line.rstrip()
