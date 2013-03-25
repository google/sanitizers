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

ifeq ($(PLATFORM), )
	PLATFORM=$(shell uname -s | sed -e "s/CYGWIN.*/Windows/" | sed -e "s/Darwin/Mac/")
endif

ifeq ($(PLATFORM), Windows)
	# TODO(timurrrr): auto-adjust when using `clang -faddress-sanitizer`?
	# Currently, I run
	# make CC=clang.exe CC_OUT="-c -o" CFLAGS=-faddress-sanitizer EXTRA_OBJ=<path_to_rtl>/asan_rtl.lib -j
	CC=cl
	CFLAGS=/TC /Zi /nologo
	LINK=link
	LINK_FLAGS=/debug /nologo /incremental:no
	LINK_OUT=/out:
	EXTRA_OBJ=
else ifeq ($(PLATFORM), Linux)
	# TODO(timurrrr): auto-adjust when using `clang -faddress-sanitizer`?
	# Currently, I run
	# make CC=clang CFLAGS=-faddress-sanitizer EXTRA_OBJ="<path_to_rtl>/libasan64.so -lpthread -ldl" -j
	CC=g++
	CFLAGS=-g
	LINK=g++
	LINK_FLAGS=
	LINK_OUT=-o
	EXTRA_OBJ=
endif
CC_OUT=-c -o
EXTRA_CFLAGS=
FILECHECK=
RM_F=del -Q

RUN_TEST_TARGETS=$(patsubst %.cpp,check_%_test,$(wildcard *.cpp))

all: run_all_tests
.PHONY: all

clean:
	$(RM_F) *.pdb *.ilk *.exe *.obj *.obj-* *.exe.manifest *.exp *.lib *.suo *.output
.PHONY: clean

run_%_pass_test: %_pass_test.exe
	@  $(TEST_COMMAND_PREFIX) ./$< || ! echo "ERROR: $< - FAILED!" >&2

check_%_pass_test: run_%_pass_test
	@echo "$< - PASSED"

run_%_stress_test: %_stress_test.exe
	@  $(TEST_COMMAND_PREFIX) ./$< || ! echo "ERROR: $< - FAILED!" >&2
	@echo "$< - PASSED"

%_crash_test.output: %_crash_test.exe
	@! $(TEST_COMMAND_PREFIX) ./$< >$@ 2>&1 || ! echo "ERROR: $< - FAILED TO CRASH!" >&2

run_%_crash_test: %_crash_test.output
	@cat $^
	@echo "$< - CRASHED AS EXPECTED"

check_%_crash_test: %_crash_test.output %_crash.cpp
	@$(FILECHECK) -input-file=$^
	@echo "$< - PASSED (CRASHED WITH THE CORRECT OUTPUT)"

.PHONY: run_%_test

%_test.exe: %.obj $(EXTRA_OBJ)
	$(LINK) $(LINK_FLAGS) $(LINK_OUT)$@ $< $(EXTRA_OBJ)

%.obj: %.cpp common.h
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) $(CC_OUT)$@ $<
	@# Automatically removes the file at the end of the run? Oh wow!

run_all_tests: $(RUN_TEST_TARGETS)
	@echo "========================================"
	@echo "ALL TESTS PASSED!"
	@echo "Please note that the crash reports above are expected, e.g. glibc printing to tty"
	@echo "Cleaning up..."
.PHONY: run_all_tests
