#!/usr/bin/python

import getopt
import os
import re
import sys
import subprocess

time_re = re.compile(
  '^(?P<time>\[[ ]*[0-9\.]+\]) ?(?P<body>.*)$'
)

frame_re = re.compile(
  '^'                                  +
  '(?P<prefix>[^\[\t]*)'               +
  '(\[\<(?P<addr>[0-9A-Fa-f]+)\>\])?'  +
  '( |\t)'                             +
  '((?P<precise>\?) )?'                +
  '(?P<body>'                          +
    '(?P<function>[^\+]+)'             +
    '\+'                               +
    '0x(?P<offset>[0-9A-Fa-f]+)'       +
    '/'                                +
    '0x(?P<size>[0-9A-Fa-f]+)'         +
    '( \[(?P<module>.+)\])?'           +
  ')$'
)

nm_re = re.compile(
  '^(?P<offset>[0-9A-Fa-f]+) [a-zA-Z] (?P<symbol>[^ ]+)$'
)

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
  path = os.path.expanduser(path)
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
        symbol = match.group('symbol')
        offset = int(match.group('offset'), 16)
        if not self.offsets.has_key(symbol):
          self.offsets[symbol] = []
        self.offsets[symbol].append(offset)

  def LookupOffsets(self, symbol):
    return self.offsets.get(symbol, [])

class ReportProcesser:
  def __init__(self, linux_path, strip_path):
    self.strip_path = strip_path
    self.linux_path = linux_path
    self.module_symbolizers = {}
    self.module_offset_loaders = {}
    self.loaded_files = {}

  def ProcessInput(self, lines_before, lines_after, questionable):
    for line in sys.stdin:
      line = line.rstrip()
      line = self.StripTime(line)
      self.ProcessLine(line, lines_before, lines_after, questionable)

  def StripTime(self, line):
    match = time_re.match(line)
    if match != None:
      line = match.group('body')
    return line

  def ProcessLine(self, line, lines_before, lines_after, questionable):
    match = frame_re.match(line)
    if match == None:
      print line
      return

    prefix = match.group('prefix')

    addr = match.group('addr')
    body = match.group('body')

    precise = match.group('precise')
    assert precise == None or precise == '?'
    precise = True if precise == None else False
    # Don't print frames with '?' until user asked otherwise.
    if not precise and not questionable:
      return

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

    symbol_offsets = loader.LookupOffsets(function)
    if len(symbol_offsets) == 0:
      print line
      return
    elif len(symbol_offsets) == 1:
      symbol_addr = symbol_offsets[0]
    else:
      # If there are more than one symbol with the same name, best-effort guess
      # the correct one by comparing 12 (log(min(PAGE_SIZE))) least significant
      # bits of the address. We can't use the whole address for this, since it
      # is subject to randomization.
      symbol_addr = None
      for symbol_offset in symbol_offsets:
        if (int(addr, 16) % (1 << 12)) == (symbol_offset % (1 << 12)):
          symbol_addr = symbol_offset
          break
      if not symbol_addr:
        print line
        return

    instruction_offset = int(offset, 16)
    module_addr = hex(symbol_addr + instruction_offset - 1);

    frames = symbolizer.Process(module_addr)

    if len(frames) == 0:
      print line
      return

    for i, frame in enumerate(frames):
      inlined = (i + 1 != len(frames))
      func, fileline = frame[0], frame[1]
      fileline = fileline.split(' (')[0] # strip ' (discriminator N)'
      self.PrintFrame(inlined, precise, prefix, addr, func, fileline, body)
      self.PrintLines(fileline, lines_before, lines_after)

  def LoadModule(self, module):
    if module in self.module_symbolizers.keys():
      return True

    module_path = FindFile(self.linux_path, module)
    if module_path == None:
      return False

    self.module_symbolizers[module] = Symbolizer(module_path)
    self.module_offset_loaders[module] = SymbolOffsetLoader(module_path)
    return True

  def LoadFile(self, path):
    if path in self.loaded_files.keys():
      return self.loaded_files[path]
    try:
      with open(path) as f:
        self.loaded_files[path] = f.readlines()
        return self.loaded_files[path]
    except:
      return None

  def PrintFrame(self, inlined, precise, prefix, addr, func, fileline, body):
    if self.strip_path != None:
      fileline_parts = fileline.split(self.strip_path, 1)
      if len(fileline_parts) >= 2:
        fileline = fileline_parts[1].lstrip('/')
    if inlined:
      addr = '     inline     ';
    elif addr == None:
      addr = '      none      ';
    precise = '' if precise else '? '
    if inlined:
      print '%s[<%s>] %s%s %s' % (prefix, addr, precise, func, fileline)
    else:
      print '%s[<%s>] %s%s %s' % (prefix, addr, precise, body, fileline)

  def PrintLines(self, fileline, lines_before, lines_after):
    if lines_before == None and lines_after == None:
      return
    lines_before = 0 if lines_before == None else lines_before
    lines_after = 0 if lines_after == None else lines_after

    fileline = fileline.split(':')
    filename, linenum = fileline[0], fileline[1]

    try:
      linenum = int(linenum)
    except:
      return
    assert linenum >= 0
    if linenum == 0: # addr2line failed to restore correct line info
      return
    linenum -= 1 # addr2line reports line numbers starting with 1

    start = max(0, linenum - lines_before)
    end = linenum + lines_after + 1
    lines = self.LoadFile(filename)
    if not lines:
      return

    for i, line in enumerate(lines[start:end]):
      print '  {0:5d} {1}'.format(i + start + 1, line),

  def Finalize(self):
    for module, symbolizer in self.module_symbolizers.items():
      symbolizer.Close()

def print_usage():
  print 'Usage: {0} --linux=<linux path>'.format(sys.argv[0]),
  print '[--strip=<strip path>]',
  print '[--before=<lines before>]',
  print '[--after=<lines after>]',
  print '[--questionable]',
  print

def main():
  try:
    opts, args = getopt.getopt(sys.argv[1:], 'l:s:b:a:q:',
		    ['linux=', 'strip=', 'before=', 'after=', 'questionable'])
  except:
    print_usage()
    sys.exit(1)

  linux_path = os.getcwd()
  strip_path = os.getcwd()
  lines_before = None
  lines_after = None
  questionable = False

  for opt, arg in opts:
    if opt in ('-l', '--linux'):
      linux_path = arg
    elif opt in ('-s', '--strip'):
      strip_path = arg
    elif opt in ('-b', '--before'):
      lines_before = arg
    elif opt in ('-a', '--after'):
      lines_after = arg
    elif opt in ('-q', '--questionable'):
      questionable = True

  try:
    lines_before = None if lines_before == None else int(lines_before)
    lines_after = None if lines_after == None else int(lines_after)
  except:
    print_usage()
    sys.exit(1)

  processer = ReportProcesser(linux_path, strip_path)
  processer.ProcessInput(lines_before, lines_after, questionable)
  processer.Finalize()

  sys.exit(0)

if __name__ == '__main__':
  main()
