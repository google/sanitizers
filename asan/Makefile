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

CLANG_SRC=$(ROOT)/../clang_src
CLANG_BUILD=$(ROOT)/../clang_build_$(OS)/Release+Asserts
CLANG_CXX=$(CLANG_BUILD)/bin/clang++
CLANG_LIB=$(CLANG_BUILD)/lib

INSTALL_DIR=../asan_clang_$(OS)
BIN=bin_$(OS)

LIBS=#-lpthread -ldl
BITS=64
SUFF=$(BITS)
ASAN_STACK=1
ifeq ($(PLATFORM),Darwin)
ASAN_GLOBALS=0
else
ASAN_GLOBALS=1
endif
ASAN_USE_CALL=1
ASAN_SCALE=0  # default will be used
ASAN_OFFSET=-1  #default will be used
ASAN_UAR=0
ASAN_HAS_EXCEPTIONS=1
ASAN_HAS_BLACKLIST=1
ASAN_NEEDS_SEGV=1

ASAN_PIE=0
PIE=
ifeq ($(ASAN_PIE), 1)
  PIE=-fPIE -pie
endif

LIBASAN_A=$(CLANG_LIB)/libasan$(SUFF).a

BLACKLIST=
ifeq ($(ASAN_HAS_BLACKLIST), 1)
  BLACKLIST=-mllvm -asan-blacklist=$(ROOT)/tests/asan_test.ignore
endif

COMMON_ASAN_DEFINES=\
                -DASAN_UAR=$(ASAN_UAR) \
		-DASAN_HAS_EXCEPTIONS=$(ASAN_HAS_EXCEPTIONS) \
		-DASAN_NEEDS_SEGV=$(ASAN_NEEDS_SEGV) \
		-DASAN_HAS_BLACKLIST=$(ASAN_HAS_BLACKLIST)

CLANG_ASAN_CXX=$(CLANG_CXX) -fasan \
		$(BLACKLIST)  \
		-mllvm -asan-stack=$(ASAN_STACK)      \
		-mllvm -asan-globals=$(ASAN_GLOBALS)  \
		-mllvm -asan-use-call=$(ASAN_USE_CALL) \
		-mllvm -asan-mapping-scale=$(ASAN_SCALE) \
		-mllvm -asan-mapping-offset-log=$(ASAN_OFFSET) \
		-mllvm -asan-use-after-return=$(ASAN_UAR) \
		$(COMMON_ASAN_DEFINES)

CLANG_ASAN_LD=$(CLANG_CXX) -fasan

GCC_ASAN_PATH=SET_FROM_COMMAND_LINE
GCC_ASAN_CXX=$(GCC_ASAN_PATH)/g++ -fasan \
	     $(COMMON_ASAN_DEFINES) \
	     -DADDRESS_SANITIZER=1
GCC_ASAN_LD=$(GCC_ASAN_PATH)/g++ -ldl -lpthread

ASAN_COMPILER=clang

ifeq ($(ASAN_COMPILER), clang)
  ASAN_CXX=$(CLANG_ASAN_CXX)
  ASAN_LD=$(CLANG_ASAN_LD)
  ASAN_LD_TAIL=
endif

ifeq ($(ASAN_COMPILER), gcc)
  ASAN_CXX=$(GCC_ASAN_CXX)
  ASAN_LD=$(GCC_ASAN_LD)
  ASAN_LD_TAIL=$(LIBASAN_A)
endif

RTL_HDR_COMMON=asan_allocator.h \
	asan_int.h \
	asan_interceptors.h \
	asan_lock.h \
	asan_mapping.h \
	asan_stack.h \
	asan_stats.h \
	asan_thread.h \
	basictypes.h \
	sysinfo.h

LIBASAN_OBJ_COMMON=$(BIN)/asan_rtl$(SUFF).o \
	    $(BIN)/asan_allocator$(SUFF).o  \
	    $(BIN)/asan_interceptors$(SUFF).o  \
	    $(BIN)/asan_stack$(SUFF).o  \
	    $(BIN)/asan_thread$(SUFF).o  \
	    $(BIN)/sysinfo$(SUFF).o


ifeq ($(PLATFORM),Darwin)
RTL_HDR=$(RTL_HDR_COMMON) mach_override.h
LIBASAN_OBJ=$(LIBASAN_OBJ_COMMON) \
	    $(BIN)/asan_malloc_mac$(SUFF).o
	    $(BIN)/mach_override$(SUFF).o
else
RTL_HDR=$(RTL_HDR_COMMON)
LIBASAN_OBJ=$(LIBASAN_OBJ_COMMON) \
	    $(BIN)/asan_malloc_linux$(SUFF).o
endif


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

lib32:
	$(MAKE) BITS=32 lib
lib64:
	$(MAKE) BITS=64 lib

$(BIN):
	mkdir -p $(BIN)

$(CLANG_LIB):
	mkdir -p $(CLANG_LIB)

clang:
	cd ../ && llvm/rebuild_clang_and_asan.sh > /dev/null

install: install_lib install_clang

$(INSTALL_DIR):
	mkdir -p $(INSTALL_DIR) $(INSTALL_DIR)/bin $(INSTALL_DIR)/lib

install_clang: | $(INSTALL_DIR)
	cp -v $(CLANG_BUILD)/bin/clang $(INSTALL_DIR)/bin
	cp -rv $(CLANG_BUILD)/lib/clang $(INSTALL_DIR)/lib
	(cd $(INSTALL_DIR)/bin; ln -sf clang clang++)

install_lib: | $(INSTALL_DIR)
	cp -v $(CLANG_BUILD)/lib/libasan*.a $(INSTALL_DIR)/lib

$(BIN)/asan_noinst_test$(SUFF).o: tests/asan_noinst_test.cc $(RTL_HDR) Makefile
	$(CLEANROOM_CXX) $(PIE) -m$(BITS) $(GTEST_INCLUDE) -I. -g -c $< -O2 -o $@

$(BIN)/asan_break_optimization$(SUFF).o: tests/asan_break_optimization.cc Makefile
	$(CLEANROOM_CXX) $(PIE) -m$(BITS) -c $< -O0 -o $@

$(BIN)/%_test$(SUFF).o: tests/%_test.cc $(RTL_HDR) Makefile
	$(ASAN_CXX) $(GTEST_INCLUDE) -I. -g -c $< -O2 -o $@ $(PIE) -m$(BITS)

$(BIN)/%_test$(SUFF).o: tests/%_test.mm $(RTL_HDR) Makefile
	$(ASAN_CXX) $(GTEST_INCLUDE) -I. -g -c $< -O2 -o $@ -ObjC $(PIE) -m$(BITS)

$(BIN)/%$(SUFF).o: %.cc $(RTL_HDR) Makefile
	$(CXX) $(PIE) -m$(BITS) -fPIC -O3 -c -o $@ -g $< -I../third_party \
		-DASAN_REVISION=\"$(SVNVERSION)\" \
		-DASAN_USE_SYSINFO=1 \
		-DASAN_NEEDS_SEGV=$(ASAN_NEEDS_SEGV) \
		-DASAN_HAS_EXCEPTIONS=$(ASAN_HAS_EXCEPTIONS) \
		$(ASAN_FLAGS)

$(BIN)/%$(SUFF).o: %.c $(RTL_HDR) Makefile
	$(CC) $(PIE) -m$(BITS) -fPIC -O3 -c -o $@ -g $< -I../third_party \
		-DASAN_REVISION=\"$(SVNVERSION)\" \
		-DASAN_USE_SYSINFO=1 \
		$(ASAN_FLAGS)

ifeq ($(PLATFORM),Darwin)
LD_FLAGS=-framework Foundation
else
LD_FLAGS=
endif

lib: $(LIBASAN_A)

$(LIBASAN_A): $(BIN) $(CLANG_LIB) $(LIBASAN_OBJ) Makefile
	ar ru $@ $(LIBASAN_OBJ)
	$(CXX) -shared -m$(BITS) $(LIBASAN_OBJ) $(LD_FLAGS) -o $(BIN)/libasan$(BITS).so


TEST_OBJECTS_COMMON=\
	     $(BIN)/asan_test$(SUFF).o \
	     $(BIN)/asan_globals_test$(SUFF).o \
	     $(BIN)/asan_break_optimization$(SUFF).o \
	     $(BIN)/asan_noinst_test$(SUFF).o

ifeq ($(PLATFORM),Darwin)
TEST_OBJECTS=$(TEST_OBJECTS_COMMON) \
	     $(BIN)/asan_mac_test$(SUFF).o
else
TEST_OBJECTS=$(TEST_OBJECTS_COMMON)
endif

$(BIN)/asan_test$(SUFF): $(TEST_OBJECTS) $(LIBASAN_A) Makefile tests/asan_test.ignore $(GTEST_LIB)
	$(ASAN_LD) $(PIE) -m$(BITS) -g -O3 $(TEST_OBJECTS) \
		$(LD_FLAGS) -o $@ $(LIBS) $(GTEST_LIB) $(ASAN_LD_TAIL)

# for now, build gtest with clang/asan even if we use a differetn compiler.
$(GTEST_LIB):
	mkdir -p $(GTEST_MAKE_DIR) && \
	cd $(GTEST_MAKE_DIR) && \
	$(MAKE) -f ../make/Makefile CXXFLAGS="$(PIE) -m$(BITS) -g -w" \
	  CXX="$(CLANG_ASAN_CXX)"

RTL_LINT_FITLER=-readability/casting,-readability/check,-build/include,-build/header_guard,-build/class,-legal/copyright
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
	rm -rf $(GTEST_ROOT)/make-*
