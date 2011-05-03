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
ASAN_CXX=../scripts/g++

LLVM_OPT=-O1
LLVM_PLUGIN=../llvm
LIBS=-lpthread
BITS=64
COMPACT=0
CROS=0

SYMBOL_TABLE_O=../third_party/gdb_symbols/symbol_table.o

RTL_SRC=asan_rtl.cc
RTL_HDR=asan_rtl.h

GTEST_ROOT=../third_party/googletest
GTEST_INCLUDE=-I$(GTEST_ROOT)/include
GTEST_MAKE_DIR=$(GTEST_ROOT)/make-$(BITS)
GTEST_LIB=$(GTEST_MAKE_DIR)/gtest-all.o


all: llvm t_cros t_64 t_64_full t_32
t_cros:
	$(MAKE) BITS=32 COMPACT=1 CROS=1 SUFF=32cros   asan_test32cros
t_64:
	$(MAKE) BITS=64 COMPACT=1 SUFF=64C1 asan_test64C1
t_64_full:
	$(MAKE) BITS=64 COMPACT=0 SUFF=64C0 asan_test64C0
t_32:
	$(MAKE) BITS=32 COMPACT=1 SUFF=32   asan_test32

SUFF=zzz

rtl: asan_rtl$(SUFF).a

llvm:
	make -C ${LLVM_PLUGIN}

asan_rtl$(SUFF).o: $(RTL_SRC) $(RTL_HDR)
	$(CXX) -m$(BITS) -DASAN_CROS=$(CROS) -DASAN_COMPACT_SHADOW=$(COMPACT) -O3 -c -o $@ -g $(RTL_SRC)

$(SYMBOL_TABLE_O):
	cd ../third_party/gdb_symbols && $(MAKE)

	
asan_rtl$(SUFF).a: asan_rtl$(SUFF).o
	ar ruv $@ $^

#asan_rtl($BITS).so: $(RTL_SRC) $(RTL_HDR)
#	$(CXX) -m$(BITS) -O3 -shared -fPIC -g $(RTL_SRC) -o $@ -lpthread

asan_test$(SUFF): asan_test.cc rtl llvm Makefile asan_test.ignore $(GTEST_LIB)
	ASAN_CROS=$(CROS) ASAN_COMPACT=$(COMPACT) ASAN_IGNORE=asan_test.ignore $(ASAN_CXX) $(GTEST_INCLUDE) -m$(BITS) -g -c $< -O2 -o $@.o
	ASAN_CROS=$(CROS) ASAN_COMPACT=$(COMPACT) $(ASAN_CXX) -m$(BITS) -g -O3 $@.o -o $@ $(LIBS) $(GTEST_LIB)

$(GTEST_LIB):
	mkdir -p $(GTEST_MAKE_DIR) && \
	cd $(GTEST_MAKE_DIR) && \
	$(MAKE) -f ../make/Makefile CXXFLAGS="-m$(BITS)"

clean:
	rm -f *.o *.ll *.S *.so *.a *.log asan_test64* asan_test32*
	make -C ${LLVM_PLUGIN} clean
