"""
Parser for unit test output in kernel logs.

Each test should write special messages to kernel log:
##### TEST_START <test_name> denotes the beginning of the test log
##### TEST_END <test_name> denotes the finnish of the test log
##### FAIL <reason> denotes the test failed
##### ASSERT '<regex>' - we should search for the regex in other lines of the
    test's output. If it's not found, the test fails
"""

import re
import sys
import difflib
import argparse

TEST_START_RE = re.compile(r"##### TEST_START (.*)$")
TEST_END_RE = re.compile(r"##### TEST_END (.*)$")
ASSERT_RE = re.compile(r"##### ASSERT '(.*)'")
FAIL_RE = re.compile(r"##### FAIL (.*)$")

parser = argparse.ArgumentParser(
    description = "Parser for unit kernel test logs from input",
    usage = "dmesg | test_parse.py [options]")

parser.add_argument("--brief", action = "store_true",
                    help = "Brief output (onlu PASSED or FAILED for each test")
parser.add_argument("--failed_log", action = "store_true",
                    help = "output full log for failed tests")
parser.add_argument("--assert_candidates", type = int, metavar = "N",
                    help = "output N closest candidates to fit the failed assert.")
parser.add_argument("--annotate", action = "store_true",
                    help = "special output for buildbot annotator")
args = parser.parse_args()

def ExtractTestLogs(kernel_log):
  all_tests = []
  current_test_lines = []
  current_test = None

  for line in sys.stdin:
    l = line.strip()
    if current_test:
      if TEST_END_RE.search(l):
        all_tests.append((current_test, current_test_lines))
        current_test = None
        current_test_lines = []
      else:
        current_test_lines.append(l)
    else:
      m = TEST_START_RE.search(l)
      if m:
        current_test = m.group(1)
  return all_tests

def FindFailures(lines):
  failures = []
  for l in lines:
    m = FAIL_RE.search(l)
    if m:
      failures.append(m.group(1))
  return failures

def FindAssertFailures(lines):
  failed_asserts = []
  for l in lines:
    m = ASSERT_RE.search(l)
    if m:
      current_assert_re = re.compile(m.group(1))
      has_matches = False
      for checkedline in lines:
        if ASSERT_RE.search(checkedline):
          continue
        if current_assert_re.search(checkedline):
          has_matches = True
          break
      if not has_matches:
        failed_asserts.append(current_assert_re.pattern)
  return failed_asserts

def PrintTestReport(test, lines, failures, failed_asserts):
  if failed_asserts or failures:
    print >> sys.stderr, "TEST %s: FAILED" % test
    if args.brief:
      return
    for f in failures:
      print >> sys.stderr, "  Failed: %s" % s
    for a in failed_asserts:
      print >> sys.stderr, "  Failed assert: %s" % a
      if args.assert_candidates:
        print >> sys.stderr, "  Closest matches:"
        for match in difflib.get_close_matches(a, lines, args.assert_candidates):
          if not ASSERT_RE.search(match):
            print  >> sys.stderr, "    " + match
    if args.failed_log:
      print "Test log:"
      for l in lines:
        print >> sys.stderr, "    " + l
  else:
    print "TEST %s: PASSED" % test

def PrintBuildBotAnnotation(passed, failed):
  print "@@@STEP_TEXT@tests: %d  passed: %d  failed: %d@@@" % (passed + failed, passed, failed)
  if failed:
    print "@@@STEP_FAILURE@@@"

def main():
  all_tests = ExtractTestLogs(sys.stdin)

  passed = 0
  failed = 0
  for test, lines in all_tests:
    failed_asserts = FindAssertFailures(lines)
    failures = FindFailures(lines)
    if failed_asserts or failures:
      failed += 1
    else:
      passed += 1
    PrintTestReport(test, lines, failures, failed_asserts)

  if args.annotate:
    PrintBuildBotAnnotation(passed, failed)

if __name__ == '__main__':
  main()
