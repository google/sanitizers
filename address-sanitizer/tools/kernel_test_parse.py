"""
Parser for unit test output in kernel logs.

Each test should write special messages to kernel log:
##### TEST_START <test_name> denotes the beginning of the test log
##### TEST_END <test_name> denotes the finnish of the test log
##### FAIL <reason> denotes the test failed
##### ASSERT '<regex>' - we should search for the regex in other lines of the
    test's output. If it's not found, the test fails
"""
from __future__ import print_function

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
parser.add_argument("--allow_flaky", nargs = '*', metavar = "name",
                    help = "allow the listed tests to be flaky")
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

def PrintTestReport(test, run_reports):
    passed = 0
    failed = 0
    for result, _, _, _ in run_reports:
        if result:
            passed += 1
        else:
            failed += 1
    if passed and not failed:
        total_result = "PASSED (%d runs)" % passed
    elif failed and not passed:
        total_result = "FAILED (%d runs)" % failed
    else:
        total_result = "FLAKY (%d passed, %d failed, %d total)" % (
                       passed, failed, passed + failed)

    print("TEST %s: %s" % (test, total_result))
    if args.brief:
        return
    for index, (_, failures, failed_asserts, lines) in enumerate(run_reports):
        if not failures and not failed_asserts:
            continue
        print("  Run %d"   % index)
        for f in failures:
            print("    Failed: %s" % f)
        missing_matches = not args.assert_candidates
        for a in failed_asserts:
            print("    Failed assert: %s" % a)
            if args.assert_candidates:
                print("    Closest matches:")
                matches =  difflib.get_close_matches(a, lines, args.assert_candidates, 0.4)
                matches = [match for match in matches if not ASSERT_RE.search(match)]
                for match in matches:
                    print("    " + match)
                if not matches:
                    missing_matches = True
        if args.failed_log and (failures or missing_matches):
            print("    Test log:")
            for l in lines:
                print("        " + l)

def PrintBuildBotAnnotation(passed, failed, flaky, flaky_not_allowed):
    if not passed and not failed and not flaky:
        print("@@@STEP_TEXT: NO TESTS WERE RUN@@@")
        print("@@@STEP_FAILURE@@@")
    print("@@@STEP_TEXT@tests:%d  passed:%d  failed:%d  flaky:%d@@@" % (passed + failed + flaky, passed, failed, flaky))
    if failed or flaky_not_allowed:
        print("@@@STEP_FAILURE@@@")

def GroupTests(tests):
    result = {}
    for test, lines in tests:
        if test not in result:
            result[test] = []
        result[test].append(lines)
    return result

def main():
    all_tests = ExtractTestLogs(sys.stdin)
    grouped_tests = GroupTests(all_tests)

    total_passed = 0
    total_failed = 0
    total_flaky = 0
    flaky_not_allowed = False
    for test, runs in grouped_tests.iteritems():
        passed = 0
        failed = 0
        run_reports = []
        for lines in runs:
            failed_asserts = FindAssertFailures(lines)
            failures = FindFailures(lines)
            if failed_asserts or failures:
                failed += 1
            else:
                passed += 1
            run_reports.append((not failed_asserts and not failures, failures, failed_asserts, lines))
        if passed and not failed:
            total_passed += 1
        elif failed and not passed:
            total_failed += 1
        else:
            total_flaky += 1
            if not args.allow_flaky or (test not in args.allow_flaky):
                flaky_not_allowed = True
        PrintTestReport(test, run_reports)

    if args.annotate:
        PrintBuildBotAnnotation(total_passed, total_failed, total_flaky, flaky_not_allowed)

if __name__ == '__main__':
    main()
