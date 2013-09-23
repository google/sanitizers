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

RUN_TEST_TARGETS=$(patsubst %.cpp,check_%_test,\
                   $(filter-out host.cpp,$(wildcard *.cpp)))
include ../common.mk

EXTRA_GUEST_LIBS=

run_%_pass_test: %_pass.dll host.exe
	@  $(TEST_COMMAND_PREFIX) ./host.exe $< || ! echo "ERROR: $< - FAILED!" >&2

%_use_after_return_crash_test.output: %_use_after_return_crash.dll host.exe
	@! $(UAR_ENV) $(TEST_COMMAND_PREFIX) ./host.exe $< >$@ 2>&1 || ! echo "ERROR: $< - FAILED TO CRASH!" >&2

%_crash_test.output: %_crash.dll host.exe
	@! $(TEST_COMMAND_PREFIX) ./host.exe $< >$@ 2>&1 || ! echo "ERROR: $< - FAILED TO CRASH!" >&2

host.exe: host.cpp ../common.h
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) $(CC_EXE_OUT)$@ $<

%.dll: %.cpp ../common.h
	$(CC) $(CC_DLL) $(CFLAGS) $(EXTRA_CFLAGS) $(CC_DLL_OUT)$@ $<
	@# Automatically removes the file at the end of the run? Oh wow!
