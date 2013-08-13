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

include ../common.mk

EXTRA_HOST_LIBS=
EXTRA_GUEST_LIBS=

default: malloc_left_oob_crash.dll host.exe
	./host.exe $<
	@echo "ALL GOOD"

host.exe: host.obj
	link -nologo -debug -out:$@ $< $(EXTRA_HOST_LIBS)

# TODO: generalize to support multiple tests
# TODO: add output checking
malloc_left_oob_crash.dll: malloc_left_oob_crash.obj
	link -nologo -debug -dll -out:$@ $< $(EXTRA_GUEST_LIBS)

%.obj: %.cpp
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) $(CC_OUT)$@ $<
