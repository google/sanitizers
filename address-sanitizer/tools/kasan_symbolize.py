#!/usr/bin/python

# Tool for symbolizing stack traces in BUG reports, mainly those produced
# by KASAN.

from collections import defaultdict
import getopt
import os
import re
import sys
import subprocess

# A hexadecimal number without the leading 0x.
HEXNUM = '[0-9A-Fa-f]+'

# An address in the form [<ffffffff12345678>].
FRAME_ADDR = (
    '(\[\<(?P<addr>' + HEXNUM + ')\>\])?\s*'
)

# A function name with an offset and function size, plus an optional module
# name, e.g.:
# __asan_load8+0x64/0x66
FRAME_BODY = (
    '(?P<body>' +
        '(?P<function>[^\+]+)' +
        '\+' +
        '0x(?P<offset>' + HEXNUM + ')' +
        '/' +
        '0x(?P<size>' + HEXNUM + ')' +
        '( \[(?P<module>.+)\])?' +
    ')')

# Matches the timestamp prefix of a log line.
TIME_RE = re.compile(
    '^(?P<time>\[[ ]*[0-9\.]+\]) ?(?P<body>.*)$'
)

# Matches a single stacktrace frame.
FRAME_RE = re.compile(
    '^' +
    '(?P<prefix>[^\[\t]*)' +
    FRAME_ADDR +
    '( |\t)' +
    '((?P<precise>\?) )?' +
    FRAME_BODY +
    '$'
)

# Matches the 'RIP:' line in BUG reports.
RIP_RE = re.compile(
    '^' +
    '(?P<prefix>\s*RIP: ' + HEXNUM + ':\[[^]]+\]\s*)' +
    FRAME_ADDR +
    FRAME_BODY +
    '$'
)

# Matches a single line of `nm -S` output.
NM_RE = re.compile(
    '^(?P<offset>' + HEXNUM + ')( (?P<size>' + HEXNUM + '))?' +
    ' [a-zA-Z] (?P<symbol>[^ ]+)$'
)


class Symbolizer(object):
    def __init__(self, binary_path):
        self.proc = subprocess.Popen(
            ['addr2line', '-f', '-i', '-e', binary_path],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE)

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.close()

    def process(self, addr):
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

    def close(self):
        self.proc.kill()
        self.proc.wait()


def find_file(path, name):
    path = os.path.expanduser(path)
    for root, dirs, files in os.walk(path):
        if name in files:
            return os.path.join(root, name)
    return None


class SymbolOffsetTable(object):
    """A table of symbol offsets.

    There can be several symbols with similar names. The only possible way to
    distinguish between them is by their size. For each symbol name we keep a
    mapping from the sizes of symbols with that name to their offsets.
    To conform with the kernel behavior, instead of the actual symbol size
    returned by nm we store the difference between the next symbol's offset and
    this symbol's offset.
    """
    def __init__(self, binary_path):
        output = subprocess.check_output(['nm', '-Sn', binary_path])
        self.offsets = defaultdict(dict)
        prev_symbol = None
        prev_offset, prev_size = 0, 0
        for line in output.split('\n'):
            match = NM_RE.match(line)
            if match != None:
                offset = int(match.group('offset'), 16)
                size = 0 if not match.group('size') else int(match.group('size'), 16)
                if prev_symbol:
                    ksyms_size = offset - prev_offset
                    if ksyms_size >= prev_size:
                        prev_size = ksyms_size
                    self.offsets[prev_symbol][prev_size] = prev_offset
                prev_symbol = match.group('symbol')
                prev_offset, prev_size = offset, size
        self.offsets[prev_symbol][0] = prev_offset

    def lookup_offset(self, symbol, size):
        offsets = self.offsets.get(symbol)
        if offsets is None:
            return None
        if (size not in offsets):
            return None
        return offsets[size]


class ReportProcessor(object):
    def __init__(self, linux_path, strip_path):
        self.strip_path = strip_path
        self.linux_path = linux_path
        self.module_symbolizers = {}
        self.module_offset_tables = {}
        self.loaded_files = {}

    def process_input(self, context_size, questionable):
        for line in sys.stdin:
            line = line.rstrip()
            line = self.strip_time(line)
            self.process_line(line, context_size, questionable)

    def strip_time(self, line):
        match = TIME_RE.match(line)
        if match != None:
            line = match.group('body')
        return line

    def process_line(self, line, context_size, questionable):
        # |RIP_RE| is less general than |FRAME_RE|, so try it first.
        match = None
        for regexp in [RIP_RE, FRAME_RE]:
            match = regexp.match(line)
            if match:
                break
        if match == None:
            print line
            return

        prefix = match.group('prefix')
        addr = match.group('addr')
        body = match.group('body')

        precise = True
        if 'precise' in match.groupdict().keys():
            precise = not match.group('precise')
        # Don't print frames with '?' until user asked otherwise.
        if not precise and not questionable:
            if '<EOI>' in match.group('prefix'):
                print match.group('prefix')
            return

        function = match.group('function')
        offset = match.group('offset')
        size = match.group('size')
        module = match.group('module')

        if module == None:
            module = 'vmlinux'
        else:
            module += '.ko'

        if not self.load_module(module):
            print line
            return

        symbolizer = self.module_symbolizers[module]
        loader = self.module_offset_tables[module]

        symbol_offset = loader.lookup_offset(function, int(size, 16))
        if symbol_offset is None:
            print line
            return

        instruction_offset = int(offset, 16)
        module_addr = hex(symbol_offset + instruction_offset - 1);

        frames = symbolizer.process(module_addr)

        if len(frames) == 0:
            print line
            return

        for i, frame in enumerate(frames):
            inlined = (i + 1 != len(frames))
            func, fileline = frame[0], frame[1]
            fileline = fileline.split(' (')[0] # strip ' (discriminator N)'
            self.print_frame(inlined, precise, prefix, addr, func, fileline,
                             body)
            self.print_lines(fileline, context_size)

    def load_module(self, module):
        if module in self.module_symbolizers.keys():
            return True

        module_path = find_file(self.linux_path, module)
        if module_path == None:
            return False

        self.module_symbolizers[module] = Symbolizer(module_path)
        self.module_offset_tables[module] = SymbolOffsetTable(module_path)
        return True

    def load_file(self, path):
        if path in self.loaded_files.keys():
            return self.loaded_files[path]
        try:
            with open(path) as f:
                self.loaded_files[path] = f.readlines()
                return self.loaded_files[path]
        except:
            return None

    def print_frame(self, inlined, precise, prefix, addr, func, fileline, body):
        if self.strip_path != None:
            fileline_parts = fileline.split(self.strip_path, 1)
            if len(fileline_parts) >= 2:
                fileline = fileline_parts[1].lstrip('/')
        if inlined:
            addr = '     inline     ';
            body = func
        elif addr == None:
            addr = '        none        ';
        precise = '' if precise else '? '
        print '%s[<%s>] %s%s %s' % (prefix, addr, precise, body, fileline)

    def print_lines(self, fileline, context_size):
        if context_size == 0:
            return
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

        start = max(0, linenum - context_size / 2)
        end = start + context_size
        lines = self.load_file(filename)
        if not lines:
            return

        for i, line in enumerate(lines[start:end]):
            print '    {0:5d} {1}'.format(i + start + 1, line),

    def finalize(self):
        for module, symbolizer in self.module_symbolizers.items():
            symbolizer.close()


def print_usage():
    print 'Usage: {0} --linux=<linux path>'.format(sys.argv[0]),
    print '[--strip=<strip path>]',
    print '[--before=<lines before>]',
    print '[--after=<lines after>]',
    print '[--questionable]',
    print


def main():
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'l:s:c:q:',
                ['linux=', 'strip=', 'context=', 'questionable'])
    except:
        print_usage()
        sys.exit(1)

    linux_path = os.getcwd()
    strip_path = os.getcwd()
    context_size = 0
    questionable = False

    for opt, arg in opts:
        if opt in ('-l', '--linux'):
            linux_path = arg
        elif opt in ('-s', '--strip'):
            strip_path = arg
        elif opt in ('-c', '--context'):
            context_size = arg
        elif opt in ('-q', '--questionable'):
            questionable = True

    try:
        if isinstance(context_size, str):
            context_size = int(context_size)
    except:
        print_usage()
        sys.exit(1)

    processor = ReportProcessor(linux_path, strip_path)
    processor.process_input(context_size, questionable)
    processor.finalize()

    sys.exit(0)


if __name__ == '__main__':
    main()
