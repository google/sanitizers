#!/usr/bin/python

import sys
import subprocess
import re

time_re = re.compile(
  '^(?P<time>\[[ ]*[0-9\.]+\]) (?P<suffix>.+)$'
)

frame_re = re.compile(
  '^  (?P<number>#[0-9]+) (?P<addr>[0-9A-Fa-f]+) (?P<offset>.+)$'
)

def print_usage():
  print 'Usage: %s <vmlinux path>' % sys.argv[0]

class Symbolizer:
  def __init__(self, vmlinux_path):
    self.proc = subprocess.Popen(['addr2line', '-f', '-i', '-e', vmlinux_path],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE)

  def __enter__(self):
    return self

  def __exit__(self, type, value, traceback):
    self.Close()

  def Process(self, addr):
    self.proc.stdin.write(addr + '\n')
    self.proc.stdin.write('ffffffffffffffff\n')
    self.proc.stdin.flush()

    result = []
    while True:
      func = self.proc.stdout.readline().rstrip()
      fileline = self.proc.stdout.readline().rstrip()
      if func == '??':
        if len(result) == 0:
          self.proc.stdout.readline()
          self.proc.stdout.readline()
        return result
      result.append((func, fileline))

  def Close(self):
    self.proc.kill()
    self.proc.wait()

def strip_time(line):
  match = time_re.match(line)
  if match != None:
    line = match.group('suffix')
  return line

def print_frame(number, addr, func, fileline, offset):
  print '  %s %s %s %s' % (number, addr, offset, fileline)

def print_inlined_frame(number, addr, func, fileline, offset):
  addr = '     inlined    ';
  print '  %s %s %s %s %s' % (number, addr, offset, func, fileline) 

def print_frames(line, symb):
  match = frame_re.match(line)
  if match == None:
    print line.rstrip()
    return
  number = match.group('number')
  addr = match.group('addr')
  offset = match.group('offset').rstrip()
  frames = symb.Process(addr)
  if len(frames) == 0:
    print line.rstrip()
    return
  for frame in frames[:-1]:
    print_inlined_frame(number, addr, frame[0], frame[1], offset)
  print_frame(number, addr, frames[-1][0], frames[-1][1], offset)

def process_report(vmlinux_path):
  with Symbolizer(vmlinux_path) as symb:
    for line in sys.stdin:
      line = strip_time(line)
      print_frames(line, symb)

def main():
  if len(sys.argv) != 2:
    print_usage()
    sys.exit(1)
  vmlinux_path = sys.argv[1]
  process_report(vmlinux_path)
  sys.exit(0)

if __name__ == '__main__':
  main()
