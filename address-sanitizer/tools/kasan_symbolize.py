#!/usr/bin/python

import sys
import subprocess
import re

regexp = re.compile(
  '(?P<prefix>.+)(?P<number>#[0-9]+) (?P<addr>[0-9A-Fa-f]+)(?P<suffix>.+)'
)

def print_usage():
  print 'Usage: %s <vmlinux path> <report path>' % sys.argv[0]

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
        return result
      result.append((func, fileline))

  def Close(self):
    self.proc.kill()
    self.proc.wait()

def process_report(vmlinux_path, report_path):
  with Symbolizer(vmlinux_path) as symb:
    with open(report_path, 'r') as report:
      for line in report:
        m = regexp.match(line)
        if m == None:
          print line,
        else:
          prefix = m.group('prefix')
          number = m.group('number')
          addr = m.group('addr')
          suffix = m.group('suffix').rstrip()
          frames = symb.Process(addr)

          for i in xrange(len(frames)):
            frame = frames[i]
            if i != len(frames) - 1:
              print '%s%s      inlined     %s %s' % \
                    (prefix, number, frame[0], frame[1]) 
            else:
              print '%s%s %s%s %s' % \
                    (prefix, number, addr, suffix, frame[1])

def main():
  if len(sys.argv) != 3:
    print_usage()
    sys.exit(1)

  vmlinux_path = sys.argv[1]
  report_path = sys.argv[2]

  process_report(vmlinux_path, report_path)
  sys.exit(0)

if __name__ == '__main__':
  main()
