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
ASAN_UAR=0

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

LIBASAN_OBJ_COMMON_MACRO=$(1)/asan_rtl$(2).o \
	    $(1)/asan_allocator$(2).o  \
	    $(1)/asan_stack$(2).o  \
	    $(1)/asan_thread$(2).o  \
	    $(1)/sysinfo$(2).o


ifeq ($(PLATFORM),Darwin)
RTL_HDR=$(RTL_HDR_COMMON) mach_override.h
LIBASAN_OBJ_MACRO=$(LIBASAN_OBJ_COMMON_MACRO) $(1)/mach_override$(2).o
else
RTL_HDR=$(RTL_HDR_COMMON)
LIBASAN_OBJ_MACRO=$(LIBASAN_OBJ_COMMON_MACRO)
endif

LIBASAN_OBJ=$(call LIBASAN_OBJ_MACRO,$(BIN),$(SUFF))
LIBASAN_OBJ_32=$(call LIBASAN_OBJ_MACRO,$(BIN),32)
LIBASAN_OBJ_64=$(call LIBASAN_OBJ_MACRO,$(BIN),64)

GTEST_ROOT=$(ROOT)/../third_party/googletest
GTEST_INCLUDE=-I$(GTEST_ROOT)/include
GTEST_MAKE_DIR=$(GTEST_ROOT)/make-$(OS)-$(BITS)
GTEST_LIB=$(GTEST_MAKE_DIR)/gtest-all.o

all: b64 b32

test: t64 t32 output_tests lint

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

lib32:	$(BIN) $(CLANG_LIB)
	$(MAKE) BITS=32 $(LIBASAN_OBJ_32)
	ar ru $(CLANG_LIB)/libasan32.a $(LIBASAN_OBJ_32)

lib64:	$(BIN) $(CLANG_LIB)
	$(MAKE) BITS=64 $(LIBASAN_OBJ_64)
	ar ru $(CLANG_LIB)/libasan64.a $(LIBASAN_OBJ_64)

$(BIN):
	mkdir -p $(BIN)

$(CLANG_LIB):
	mkdir -p $(CLANG_LIB)

clang:
	cd ../ && llvm/rebuild_clang_and_asan.sh > /dev/null

install:
	rm -rf $(INSTALL_DIR)
	mkdir  $(INSTALL_DIR) $(INSTALL_DIR)/bin $(INSTALL_DIR)/lib
	cp -v $(CLANG_BUILD)/bin/clang $(INSTALL_DIR)/bin
	cp -v $(CLANG_BUILD)/lib/libasan*.a $(INSTALL_DIR)/lib
	cp -rv $(CLANG_BUILD)/lib/clang $(INSTALL_DIR)/lib
	(cd $(INSTALL_DIR)/bin; ln -s clang clang++)

# install_lib{32,64} are for Chromium OS only.
install_lib32:
	mkdir  $(INSTALL_DIR) $(INSTALL_DIR)/lib
	cp -v $(CLANG_BUILD)/lib/libasan32.a $(INSTALL_DIR)/lib

install_lib64:
	mkdir  $(INSTALL_DIR) $(INSTALL_DIR)/lib
	cp -v $(CLANG_BUILD)/lib/libasan64.a $(INSTALL_DIR)/lib

$(BIN)/asan_noinst_test$(SUFF).o: tests/asan_noinst_test.cc $(RTL_HDR) Makefile
	$(CLEANROOM_CXX) -m$(BITS) $(GTEST_INCLUDE) -I. -g -c $< -O2 -o $@

$(BIN)/%_test$(SUFF).o: tests/%_test.cc $(RTL_HDR) Makefile
	$(CLANG_CXX) -fasan $(GTEST_INCLUDE) -I. -g -c $< -O2 -o $@ \
		-m$(BITS)                             \
		-mllvm -asan-blacklist=tests/asan_test.ignore  \
		-mllvm -asan-stack=$(ASAN_STACK)      \
		-mllvm -asan-globals=$(ASAN_GLOBALS)  \
		-mllvm -asan-use-call=$(ASAN_USE_CALL) \
		-mllvm -asan-mapping-scale=$(ASAN_SCALE) \
		-mllvm -asan-mapping-offset-log=$(ASAN_OFFSET) \
		-mllvm -asan-use-after-return=$(ASAN_UAR) -DASAN_UAR=$(ASAN_UAR)

$(BIN)/%_test$(SUFF).o: tests/%_test.mm $(RTL_HDR) Makefile
	$(CLANG_CXX) -fasan $(GTEST_INCLUDE) -I. -g -c $< -O2 -o $@ -ObjC \
		-m$(BITS)                             \
		-mllvm -asan-blacklist=tests/asan_test.ignore  \
		-mllvm -asan-stack=$(ASAN_STACK)      \
		-mllvm -asan-globals=$(ASAN_GLOBALS)  \
		-mllvm -asan-use-call=$(ASAN_USE_CALL)

$(BIN)/%$(SUFF).o: %.cc $(RTL_HDR) Makefile
	$(CXX) -m$(BITS) -fPIC -O3 -c -o $@ -g $< -I../third_party \
		-DASAN_REVISION=\"$(SVNVERSION)\" \
		-DASAN_USE_SYSINFO=1 \
		$(ASAN_FLAGS)

$(BIN)/%$(SUFF).o: %.c $(RTL_HDR) Makefile
	$(CC) -m$(BITS) -fPIC -O3 -c -o $@ -g $< -I../third_party \
		-DASAN_REVISION=\"$(SVNVERSION)\" \
		-DASAN_USE_SYSINFO=1 \
		$(ASAN_FLAGS)

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

RTL_LINT_FITLER=-readability/casting,-readability/check,-build/include,-build/header_guard,-build/class
# TODO(kcc): remove these filters one by one
TEST_LINT_FITLER=-readability/casting,-build/include,-legal/copyright,-whitespace/newline,-runtime/sizeof,-runtime/int,-runtime/printf

LLVM_LINT_FILTER=-,+whitespace

lint:
	../third_party/cpplint/cpplint.py --filter=$(LLVM_LINT_FILTER) ../llvm/AddressSanitizer.cpp
	../third_party/cpplint/cpplint.py --filter=$(RTL_LINT_FITLER) asan_*.cc asan_*.h
	../third_party/cpplint/cpplint.py --filter=$(TEST_LINT_FITLER) tests/*.cc

clean:
	rm -f *.o *.ll *.S *.a *.log asan_test64* asan_test32*  a.out perf.data log
	rm -f $(CLANG_LIB)/libasan*
	rm -rf $(BIN)
