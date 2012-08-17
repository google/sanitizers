ROOT=$(shell pwd)

GTEST_ROOT=third_party/googletest
GTEST_INCLUDE=-I$(GTEST_ROOT)/include
GTEST_BUILD_DIR=$(GTEST_ROOT)/build
GTEST_LIB=$(GTEST_BUILD_DIR)/gtest-all.o

INTERCEPTION=../interception
COMMON=../sanitizer_common
RTL_HDR=$(wildcard *.h) \
	$(wildcard $(INTERCEPTION)/*.h) \
	$(wildcard $(COMMON)/*.h)

LIBMSAN_SRC= msan.cc \
	     msan_allocator.cc \
	     msan_interceptors.cc

INTERCEPTION_SRC=$(wildcard $(INTERCEPTION)/*.cc)
COMMON_SRC=$(wildcard $(COMMON)/*.cc)

LIBMSAN_OBJ=$(patsubst %.cc,%.o,$(LIBMSAN_SRC)) \
	    $(patsubst $(INTERCEPTION)/%.cc,%.o,$(INTERCEPTION_SRC)) \
	    $(patsubst $(COMMON)/%.cc,%.o,$(COMMON_SRC))


#CXX=$(HOME)/llvm_msan/build/Release+Asserts/bin/clang++
CLANG_BUILD=$(ROOT)/../../../../build/Release+Asserts
CXX=$(CLANG_BUILD)/bin/clang++
CXXFLAGS=-fPIE -g -O1 -fno-exceptions
RTL_CXXFLAGS=$(CXXFLAGS) -ffreestanding -fno-exceptions
LDFLAGS=-pie
MSAN_EXTRA_OPT=
MSAN_OPT=-fmemory-sanitizer $(MSAN_EXTRA_OPT)
# MSAN_DEBUG=-mllvm -debug-only=msan
CLANG_VERSION=3.2
ARCH=x86_64
OS=$(shell uname | tr '[A-Z]' '[a-z]')
LIBMSAN_INST_DIR=$(CLANG_BUILD)/lib/clang/$(CLANG_VERSION)/lib/$(OS)
LIBMSAN_A=$(LIBMSAN_INST_DIR)/libclang_rt.msan-$(ARCH).a

all: msan_test

libmsandr_test.so: msandr_test_so.cc $(GTEST_LIB)
	$(CXX) -shared -fPIC -g -O1 $< -o $@

msan_test: msan_test.cc libmsandr_test.so $(GTEST_LIB) $(LIBMSAN_A)
	$(CXX) $(CXXFLAGS) $(MSAN_DEBUG) $(GTEST_INCLUDE) -I.. $(MSAN_OPT) \
		$< -L. -lmsandr_test $(GTEST_LIB) -o $@ -ldl $(LDFLAGS) -Wl,-rpath=$(ROOT)

msan.a: $(LIBMSAN_OBJ)
	ar ru $@ $^


install: $(LIBMSAN_A)

$(LIBMSAN_A): msan.a
	cp $< $@

%.o: %.cc $(RTL_HDR)
	$(CXX) $(RTL_CXXFLAGS) -c $< -o $@ -I..

%.o: ../interception/%.cc
	$(CXX) $(RTL_CXXFLAGS) -c $< -o $@
%.o: $(COMMON)/%.cc
	$(CXX) $(RTL_CXXFLAGS) -I.. -c $< -o $@

t:
	(ulimit -s 4096; make clean && make -j 10 2> log && ./msan_test --gtest_filter=-MemorySanitizerDr.*)


# Do once: cmake -DCMAKE_BUILD_TYPE=Release -DLLVM_ENABLE_ASSERTIONS=ON  ~/llvm_msan/

install_deps:
	rm -rf third_party
	mkdir third_party
	(cd third_party && \
	svn co -r613 http://googletest.googlecode.com/svn/trunk googletest)


gtest: $(GTEST_LIB)

$(GTEST_LIB):
	mkdir -p $(GTEST_BUILD_DIR) && \
	cd $(GTEST_BUILD_DIR) && \
	$(MAKE) -f ../make/Makefile CXXFLAGS="$(CXXFLAGS)" CFLAGS="$(CFLAGS)" CC=$(CC) CXX=$(CXX)

clean: 
	rm -f *.o msan_test msan.a $(LIBMSAN_A)
