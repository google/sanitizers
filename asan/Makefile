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

PLATFORM=$(shell uname -s | sed -e "s/CYGWIN.*/Windows/" | sed -e "s/Darwin/Mac/")
SVNVERSION=$(shell svnversion)

CC=gcc
CXX=g++

CLANG_SRC=../clang_src
CLANG_BUILD=../clang_build/Release+Asserts
CLANG_CXX=$(CLANG_BUILD)/bin/clang++
CLANG_LIB=$(CLANG_BUILD)/lib

INSTALL_DIR=../asan_clang_$(PLATFORM)

LIBS=#-lpthread -ldl
BITS=64
BYTE_TO_BYTE=0
CROS=0
ASAN_STACK=1

RTL_SRC=asan_rtl.cc
RTL_HDR=asan_rtl.h

GTEST_ROOT=../third_party/googletest
GTEST_INCLUDE=-I$(GTEST_ROOT)/include
GTEST_MAKE_DIR=$(GTEST_ROOT)/make-$(BITS)
GTEST_LIB=$(GTEST_MAKE_DIR)/gtest-all.o


all: t_cros t_64 t_64full t_32
t_cros:
	$(MAKE) BITS=32 BYTE_TO_BYTE=0 CROS=1 SUFF=32cros   asan_test32cros
t_64:
	$(MAKE) BITS=64 BYTE_TO_BYTE=0 SUFF=64 asan_test64
t_64full:
	$(MAKE) BITS=64 BYTE_TO_BYTE=1 SUFF=64full asan_test64full
t_32:
	$(MAKE) BITS=32 BYTE_TO_BYTE=0 SUFF=32   asan_test32

SUFF=zzz

clang:
	cd ../ && llvm/rebuild_clang_and_asan.sh > /dev/null

install:
	rm -rf $(INSTALL_DIR)
	mkdir  $(INSTALL_DIR) $(INSTALL_DIR)/bin $(INSTALL_DIR)/lib
	for f in clang; do cp $(CLANG_BUILD)/bin/$$f $(INSTALL_DIR)/bin/$$f; done
	for f in clang libasan32.a libasan64.a; do cp -r $(CLANG_BUILD)/lib/$$f $(INSTALL_DIR)/lib/$$f; done
	(cd $(INSTALL_DIR)/bin; ln -s clang clang++)

libasan$(SUFF).o: $(RTL_SRC) $(RTL_HDR) Makefile
	$(CXX)  -O3 -c -o $@ -g $(RTL_SRC) -I../third_party -DASAN_REVISION=\"$(SVNVERSION)\" \
	   -m$(BITS) -DASAN_CROS=$(CROS) -fPIC -DASAN_BYTE_TO_BYTE_SHADOW=$(BYTE_TO_BYTE)

libasan$(SUFF).so: libasan$(SUFF).o
	$(CXX) -m$(BITS) -O3 -o $@ -g -shared -fPIC $^ -lpthread -ldl

bfds$(SUFF):
	mkdir -p $@
	cp ../third_party/bin/bfd_symbolizer/linux/bfds$(BITS).a $@/bfds$(SUFF).a
	cd $@ && ar x bfds$(SUFF).a

$(CLANG_LIB)/libasan$(SUFF).a: libasan$(SUFF).o bfds$(SUFF)
	ar ruv $@ $< bfds$(SUFF)/*.o

asan_test$(SUFF): asan_test.cc $(CLANG_LIB)/libasan$(SUFF).a Makefile $(CLANG_LIB)/libasan$(SUFF).a asan_test.ignore $(GTEST_LIB) libasan$(SUFF).so
	$(CLANG_CXX) -fasan $(GTEST_INCLUDE) -g -c $< -O2 -o $@.o \
		-m$(BITS) \
		-mllvm -asan-ignore=asan_test.ignore \
		-mllvm -asan-vmsplit2g=$(CROS) \
		-mllvm -asan-stack=$(ASAN_STACK) \
		-mllvm -asan-byte-to-byte-shadow=$(BYTE_TO_BYTE)
	ASAN_LIB=$(CLANG_LIB)/libasan$(SUFF).a \
	$(CLANG_CXX) -fasan -m$(BITS) -g -O3 $@.o -o $@ $(LIBS) $(GTEST_LIB)

$(GTEST_LIB):
	mkdir -p $(GTEST_MAKE_DIR) && \
	cd $(GTEST_MAKE_DIR) && \
	$(MAKE) -f ../make/Makefile CXXFLAGS="-m$(BITS)"

clean:
	rm -f *.o *.ll *.S *.so *.a *.log asan_test64* asan_test32*  a.out perf.data log
	rm -rf bfds*
