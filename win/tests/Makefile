# Copyright 2012 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# This file is a part of AddressSanitizer, an address sanity checker.

PLATFORM=$(shell uname -s | sed -e "s/CYGWIN.*/Windows/" | sed -e "s/Darwin/Mac/")
ifeq ($(PLATFORM), Windows)
	# TODO(timurrrr): auto-adjust when using `clang -faddress-sanitizer`?
	CC=cl
	CC_OUT=/Fe
	CFLAGS=/TC /Zi /nologo
	POST_CFLAGS=/link "/INCREMENTAL:NO"
else ifeq ($(PLATFORM), Linux)
	CC=gcc
	CC_OUT=-o
	CFLAGS=-g
	POST_CFLAGS=
endif
EXTRA_CFLAGS=

RUN_TEST_TARGETS=$(patsubst %.c,run_%_test,$(wildcard *.c))

all: run_all_tests
.PHONY: all

clean:
	rm -rf *.pdb *.ilk *.exe *.obj
.PHONY: clean

run_%_pass_test: %_pass_test.exe
	@  $(TEST_COMMAND_PREFIX) ./$< || ! echo "ERROR: $< - FAILED!" >&2
	@echo "$< - PASSED"

# TODO(timurrrr): check the output against a pattern?
run_%_crash_test: %_crash_test.exe
	@! $(TEST_COMMAND_PREFIX) ./$< || ! echo "ERROR: $< - FAILED TO CRASH!" >&2
	@echo "$< - PASSED"

.PHONY: run_%_test

%_test.exe: %.c
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) $(CC_OUT) $@ $< $(POST_CFLAGS)
	@# Automatically removes the file at the end of the run? Oh wow!

run_all_tests: $(RUN_TEST_TARGETS)
	@echo "========================================"
	@echo "ALL TESTS PASSED!"
	@echo "Please note that the crash reports above are expected, e.g. glibc printing to tty"
	@echo "Cleaning up..."
.PHONY: run_all_tests
