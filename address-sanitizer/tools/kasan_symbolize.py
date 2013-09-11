#!/usr/bin/python

import sys
import subprocess
import re

regexp = re.compile(
  '^  (?P<number>#[0-9]+) (?P<addr>[0-9A-Fa-f]+) (?P<suffix>.+)$'
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

def print_frame(number, addr, func, fileline, suffix):
  print '  %s %s %s %s' % (number, addr, suffix, fileline)

def print_inlined_frame(number, addr, func, fileline, suffix):
  addr = '     inlined    ';
  print '  %s %s %s %s %s' % (number, addr, suffix, func, fileline) 

def process_report(vmlinux_path):
  with Symbolizer(vmlinux_path) as symb:
    for line in sys.stdin:
      line = line.partition(']')[2][1:]
      match = regexp.match(line)
      if match == None:
        print line.rstrip()
      else:
        number = match.group('number')
        addr = match.group('addr')
        suffix = match.group('suffix')
        frames = symb.Process(addr)
        if len(frames) == 0:
          print line.rstrip()
        else:
          for frame in frames[:-1]:
            print_inlined_frame(number, addr, frame[0], frame[1], suffix)
          print_frame(number, addr, frames[-1][0], frames[-1][1], suffix)

def main():
  if len(sys.argv) != 2:
    print_usage()
    sys.exit(1)
  vmlinux_path = sys.argv[1]
  process_report(vmlinux_path)
  sys.exit(0)

if __name__ == '__main__':
  main()
