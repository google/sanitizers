#!/usr/bin/python

import os
import re
import sys
import subprocess

time_re = re.compile(
  '^(?P<time>\[[ ]*[0-9\.]+\]) ?(?P<suffix>.*)$'
)

frame_re = re.compile(
  '^ \[\<(?P<addr>[0-9A-Fa-f]+)\>\] ' + 
  '(\? )?'                            +
  '(?P<suffix>'                       +
    '(?P<function>[^\+]+)'            +
    '\+'                              +
    '0x(?P<offset>[0-9A-Fa-f]+)'      +
    '/'                               +
    '0x(?P<size>[0-9A-Fa-f]+)'        +
    '( \[(?P<module>.+)\])?'          +
  ')$'
)

nm_re = re.compile(
  '^(?P<offset>[0-9A-Fa-f]+) [a-zA-Z] (?P<symbol>[^ ]+)$'
)

def print_usage():
  print 'Usage: %s <linux path> [<strip path>]' % sys.argv[0]

class Symbolizer:
  def __init__(self, binary_path):
    self.proc = subprocess.Popen(['addr2line', '-f', '-i', '-e', binary_path],
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

def FindFile(path, name):
  for root, dirs, files in os.walk(path):
    if name in files:
      return os.path.join(root, name)
  return None

class SymbolOffsetLoader:
  def __init__(self, binary_path):
    output = subprocess.check_output(['nm', binary_path])
    self.offsets = {}
    for line in output.split('\n'):
      match = nm_re.match(line)
      if match != None:
        self.offsets[match.group('symbol')] = int(match.group('offset'), 16)

  def LookupOffset(self, symbol):
    return self.offsets.get(symbol)

class ReportProcesser:
  def __init__(self, linux_path, strip_path):
    self.strip_path = strip_path
    self.linux_path = linux_path
    self.module_symbolizers = {}
    self.module_offset_loaders = {}

  def ProcessInput(self):
    for line in sys.stdin:
      line = line.rstrip()
      line = self.StripTime(line)
      self.ProcessLine(line)

  def StripTime(self, line):
    match = time_re.match(line)
    if match != None:
      line = match.group('suffix')
    return line

  def ProcessLine(self, line):
    match = frame_re.match(line)
    if match == None:
      print line
      return

    addr = match.group('addr')
    suffix = match.group('suffix')

    function = match.group('function')
    offset = match.group('offset')
    size = match.group('size')
    module = match.group('module')

    if module == None:
      module = 'vmlinux'
    else:
      module += '.ko'

    frames = []

    if not self.LoadModule(module):
      print line
      return

    symbolizer = self.module_symbolizers[module]
    loader = self.module_offset_loaders[module]

    symbol_offset = loader.LookupOffset(function)
    if not symbol_offset:
      print line
      return

    instruction_offset = int(offset, 16)
    module_addr = hex(symbol_offset + instruction_offset - 1);

    frames = symbolizer.Process(module_addr)

    if len(frames) == 0:
      print line
      return

    for frame in frames[:-1]:
      self.PrintInlinedFrame(addr, frame[0], frame[1], suffix)
    self.PrintFrame(addr, frames[-1][0], frames[-1][1], suffix)

  def LoadModule(self, module):
    if module in self.module_symbolizers.keys():
      return True

    module_path = FindFile(self.linux_path, module)
    if module_path == None:
      return False

    self.module_symbolizers[module] = Symbolizer(module_path)
    self.module_offset_loaders[module] = SymbolOffsetLoader(module_path)
    return True

  def PrintFrame(self, addr, func, fileline, suffix):
    if self.strip_path != None:
      fileline_parts = fileline.split(self.strip_path)
      if len(fileline_parts) >= 2:
        fileline = fileline_parts[1].lstrip('/')
    print ' [<%s>] %s %s' % (addr, suffix, fileline)

  def PrintInlinedFrame(self, addr, func, fileline, suffix):
    if self.strip_path != None:
      fileline_parts = fileline.split(self.strip_path)
      if len(fileline_parts) >= 2:
        fileline = fileline_parts[1].lstrip('/')
    addr = '     inlined    ';
    print ' [<%s>] %s %s %s' % (addr, suffix, func, fileline) 

  def Finalize(self):
    for module, symbolizer in self.module_symbolizers.items():
      symbolizer.Close()

def main():
  if len(sys.argv) not in [2, 3]:
    print_usage()
    sys.exit(1)
  linux_path = sys.argv[1]
  strip_path = sys.argv[2] if len(sys.argv) == 3 else None
  processer = ReportProcesser(linux_path, strip_path)
  processer.ProcessInput()
  processer.Finalize()
  sys.exit(0)

if __name__ == '__main__':
  main()
