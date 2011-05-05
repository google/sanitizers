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

CC=gcc
CXX=g++

CLANG_SRC=../clang_src
CLANG_BUILD=../clang_build
CLANG_BUILD_TYPE=Debug+Asserts
CLANG_CXX=$(CLANG_BUILD)/$(CLANG_BUILD_TYPE)/bin/clang++

LIBS=-lpthread
BITS=64
BYTE_TO_BYTE=0
CROS=0

SYMBOL_TABLE_O=../third_party/gdb_symbols/symbol_table.o

RTL_SRC=asan_rtl.cc
RTL_HDR=asan_rtl.h

GTEST_ROOT=../third_party/googletest
GTEST_INCLUDE=-I$(GTEST_ROOT)/include
GTEST_MAKE_DIR=$(GTEST_ROOT)/make-$(BITS)
GTEST_LIB=$(GTEST_MAKE_DIR)/gtest-all.o


all: t_cros t_64 t_64_full t_32
t_cros:
	$(MAKE) BITS=32 BYTE_TO_BYTE=0 CROS=1 SUFF=32cros   asan_test32cros
t_64:
	$(MAKE) BITS=64 BYTE_TO_BYTE=0 SUFF=64 asan_test64
t_64_full:
	$(MAKE) BITS=64 BYTE_TO_BYTE=1 SUFF=64full asan_test64full
t_32:
	$(MAKE) BITS=32 BYTE_TO_BYTE=0 SUFF=32   asan_test32

SUFF=zzz

rtl: asan_rtl$(SUFF).a

asan_rtl$(SUFF).o: $(RTL_SRC) $(RTL_HDR)
	$(CXX)  -O3 -c -o $@ -g $(RTL_SRC) \
	   -m$(BITS) -DASAN_CROS=$(CROS) -DASAN_BYTE_TO_BYTE_SHADOW=$(BYTE_TO_BYTE)


$(SYMBOL_TABLE_O):
	cd ../third_party/gdb_symbols && $(MAKE)

	
asan_rtl$(SUFF).a: asan_rtl$(SUFF).o
	ar ruv $@ $^

#asan_rtl($BITS).so: $(RTL_SRC) $(RTL_HDR)
#	$(CXX) -m$(BITS) -O3 -shared -fPIC -g $(RTL_SRC) -o $@ -lpthread

asan_test$(SUFF): asan_test.cc asan_rtl$(SUFF).a Makefile asan_test.ignore $(GTEST_LIB)
	$(CLANG_CXX) $(GTEST_INCLUDE) -g -c $< -O2 -o $@.o \
		-m$(BITS) \
		-mllvm -asan-ignore=asan_test.ignore \
		-mllvm -asan-cros=$(CROS) \
		-mllvm -asan-byte-to-byte-shadow=$(BYTE_TO_BYTE)
	$(CLANG_CXX) -m$(BITS) -g -O3 $@.o -o $@ $(LIBS) $(GTEST_LIB) asan_rtl$(SUFF).a

$(GTEST_LIB):
	mkdir -p $(GTEST_MAKE_DIR) && \
	cd $(GTEST_MAKE_DIR) && \
	$(MAKE) -f ../make/Makefile CXXFLAGS="-m$(BITS)"

clean:
	rm -f *.o *.ll *.S *.so *.a *.log asan_test64* asan_test32*
