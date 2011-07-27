#  Copyright 2011 Google Inc.
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

SVNVERSION=$(shell svnversion)
OS=$(shell uname)
ROOT=$(shell pwd)
PLATFORM=$(shell uname)

CXX=g++ -Wall -fvisibility=hidden
CC=gcc -Wall -fvisibility=hidden
CLEANROOM_CXX=g++ -Wall

CLANG_SRC=../clang_src
CLANG_BUILD=../clang_build_$(OS)/Release+Asserts
CLANG_CXX=$(CLANG_BUILD)/bin/clang++
CLANG_LIB=$(CLANG_BUILD)/lib

INSTALL_DIR=../asan_clang_$(OS)
BIN=bin_$(OS)

LIBS=#-lpthread -ldl
BITS=64
ASAN_STACK=1
ifeq ($(PLATFORM),Darwin)
ASAN_GLOBALS=0
else
ASAN_GLOBALS=1
endif
ASAN_USE_CALL=0
ASAN_SCALE=0  # default will be used
ASAN_OFFSET=0  #default will be used
ASAN_BTS=0

RTL_HDR_COMMON=asan_allocator.h \
	asan_int.h \
	asan_lock.h \
	asan_mapping.h \
	asan_stack.h \
	asan_stats.h \
	asan_thread.h \
	basictypes.h \
	sysinfo.h

SUFF=$(BITS)
LIBASAN_OBJ_COMMON=$(BIN)/asan_rtl$(SUFF).o \
	    $(BIN)/asan_allocator$(SUFF).o  \
	    $(BIN)/asan_stack$(SUFF).o  \
	    $(BIN)/asan_thread$(SUFF).o  \
	    $(BIN)/sysinfo$(SUFF).o

ifeq ($(PLATFORM),Darwin)
RTL_HDR=$(RTL_HDR_COMMON) mach_override.h
LIBASAN_OBJ=$(LIBASAN_OBJ_COMMON) $(BIN)/mach_override$(SUFF).o
else
RTL_HDR=$(RTL_HDR_COMMON)
LIBASAN_OBJ=$(LIBASAN_OBJ_COMMON)
endif

GTEST_ROOT=$(ROOT)/../third_party/googletest
GTEST_INCLUDE=-I$(GTEST_ROOT)/include
GTEST_MAKE_DIR=$(GTEST_ROOT)/make-$(OS)-$(BITS)
GTEST_LIB=$(GTEST_MAKE_DIR)/gtest-all.o

all: b64 b32

test: t64 t32 output_tests

output_tests: b32 b64
	cd tests && ./test_output.sh

t64: b64
	$(BIN)/asan_test64
t32: b32
	$(BIN)/asan_test32

b64: | $(BIN)
	$(MAKE) BITS=64 $(BIN)/asan_test64
b32: | $(BIN)
	$(MAKE) BITS=32 $(BIN)/asan_test32


$(BIN):
	mkdir -p $(BIN)

clang:
	cd ../ && llvm/rebuild_clang_and_asan.sh > /dev/null

install:
	rm -rf $(INSTALL_DIR)
	mkdir  $(INSTALL_DIR) $(INSTALL_DIR)/bin $(INSTALL_DIR)/lib
	for f in clang; do cp $(CLANG_BUILD)/bin/$$f $(INSTALL_DIR)/bin/$$f; done
	for f in clang libasan32.a libasan64.a; do cp -r $(CLANG_BUILD)/lib/$$f $(INSTALL_DIR)/lib/$$f; done
	(cd $(INSTALL_DIR)/bin; ln -s clang clang++)

$(BIN)/asan_noinst_test$(SUFF).o: tests/asan_noinst_test.cc $(RTL_HDR) Makefile
	$(CLEANROOM_CXX) -m$(BITS) $(GTEST_INCLUDE) -I. -g -c $< -O2 -o $@

$(BIN)/%_test$(SUFF).o: tests/%_test.cc $(RTL_HDR) Makefile
	$(CLANG_CXX) -fasan $(GTEST_INCLUDE) -I. -g -c $< -O2 -o $@ \
		-m$(BITS)                             \
		-mllvm -asan-black-list=tests/asan_test.ignore  \
		-mllvm -asan-stack=$(ASAN_STACK)      \
		-mllvm -asan-globals=$(ASAN_GLOBALS)  \
		-mllvm -asan-use-call=$(ASAN_USE_CALL) \
		-mllvm -asan-mapping-scale=$(ASAN_SCALE) \
		-mllvm -asan-mapping-offset-log=$(ASAN_OFFSET) \
		-mllvm -asan-use-bts=$(ASAN_BTS)

$(BIN)/%_test$(SUFF).o: tests/%_test.mm $(RTL_HDR) Makefile
	$(CLANG_CXX) -fasan $(GTEST_INCLUDE) -I. -g -c $< -O2 -o $@ -ObjC \
		-m$(BITS)                             \
		-mllvm -asan-black-list=tests/asan_test.ignore  \
		-mllvm -asan-stack=$(ASAN_STACK)      \
		-mllvm -asan-globals=$(ASAN_GLOBALS)  \
		-mllvm -asan-use-call=$(ASAN_USE_CALL)

$(BIN)/%$(SUFF).o: %.cc $(RTL_HDR) Makefile
	$(CXX) -m$(BITS) -fPIC -O3 -c -o $@ -g $< -I../third_party \
		-DASAN_REVISION=\"$(SVNVERSION)\" \
		-DASAN_USE_SYSINFO=1

$(BIN)/%$(SUFF).o: %.c $(RTL_HDR) Makefile
	$(CC) -m$(BITS) -fPIC -O3 -c -o $@ -g $< -I../third_party \
		-DASAN_REVISION=\"$(SVNVERSION)\" \
		-DASAN_USE_SYSINFO=1

ifeq ($(PLATFORM),Darwin)
LD_FLAGS=-framework Foundation
else
LD_FLAGS=
endif

$(CLANG_LIB)/libasan$(SUFF).a: $(LIBASAN_OBJ) | Makefile
	ar ru $@ $^


ifeq ($(PLATFORM),Darwin)
TEST_OBJECTS=\
	     $(BIN)/asan_test$(SUFF).o \
	     $(BIN)/asan_globals_test$(SUFF).o \
	     $(BIN)/asan_noinst_test$(SUFF).o \
	     $(BIN)/asan_mac_test$(SUFF).o
else
TEST_OBJECTS=\
	     $(BIN)/asan_test$(SUFF).o \
	     $(BIN)/asan_globals_test$(SUFF).o \
	     $(BIN)/asan_noinst_test$(SUFF).o
LD_FLAGS=
endif

$(BIN)/asan_test$(SUFF): $(TEST_OBJECTS)  $(CLANG_LIB)/libasan$(SUFF).a Makefile $(CLANG_LIB)/libasan$(SUFF).a tests/asan_test.ignore $(GTEST_LIB)
	$(CLANG_CXX) -fasan -m$(BITS) -g -O3 $(TEST_OBJECTS) $(LD_FLAGS) -o $@ $(LIBS) $(GTEST_LIB)

$(GTEST_LIB):
	mkdir -p $(GTEST_MAKE_DIR) && \
	cd $(GTEST_MAKE_DIR) && \
	$(MAKE) -f ../make/Makefile CXXFLAGS="-m$(BITS) -g"

# TODO(kcc): remove these filters one by one
LINT_FITLER=-build,-readability,-whitespace

lint:
	../third_party/cpplint/cpplint.py --filter=$(LINT_FITLER) asan_*.cc asan_*.h

clean:
	rm -f *.o *.ll *.S *.a *.log asan_test64* asan_test32*  a.out perf.data log
	rm -f $(CLANG_LIB)/libasan*
	rm -rf $(BIN)
