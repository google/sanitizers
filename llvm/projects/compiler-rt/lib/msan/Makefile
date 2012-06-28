GTEST_ROOT=third_party/googletest
GTEST_INCLUDE=-I$(GTEST_ROOT)/include
GTEST_BUILD_DIR=$(GTEST_ROOT)/build
GTEST_LIB=$(GTEST_BUILD_DIR)/gtest-all.o

PIN=$(HOME)/pin_msan
MSAN_PIN_DIR=$(PIN)/source/tools/SimpleExamples
MSAN_PIN_SO=$(MSAN_PIN_DIR)/obj-intel64/msan_pin.so

#CXX=$(HOME)/llvm_msan/build/Release+Asserts/bin/clang++
CXX=clang++
CXXFLAGS=-fPIE -g -O1 -fno-exceptions
LDFLAGS=-pie -lpthread
# MSAN_DEBUG=-mllvm -debug-only=msan

all: msan_test pin

msan_test: msan_test.cc msan.a $(GTEST_LIB) -ldl
	$(CXX) $(CXXFLAGS) $(MSAN_DEBUG) $(GTEST_INCLUDE) -fmemory-sanitizer $^ -o $@ $(LDFLAGS)

msan.a: msan.o interception.o
	ar ru $@ $^

msan.o: msan.cc msan_linux_inl.h
	$(CXX) $(CXXFLAGS) -c $< -o $@ -Ithird_party

interception.o: third_party/interception/interception_linux.cc
	$(CXX) $(CXXFLAGS) -c $< -o $@

pin: $(MSAN_PIN_SO)

$(MSAN_PIN_SO): msan_pin.cpp
	cd $(MSAN_PIN_DIR) && make

t:
	(ulimit -s 4096; make clean && make -j 10 2> log && ./msan_test )


# Do once: cmake -DCMAKE_BUILD_TYPE=Release -DLLVM_ENABLE_ASSERTIONS=ON  ~/llvm_msan/

clang:
	cd ~/llvm_msan/cmake_build; make -j16 > /dev/null
#	cd ~/llvm_msan/build; make -j16 > /dev/null

install_deps:
	rm -rf third_party
	mkdir third_party
	(cd third_party && \
	svn co -r613 http://googletest.googlecode.com/svn/trunk googletest &&\
	svn co  http://llvm.org/svn/llvm-project/compiler-rt/trunk/lib/interception)


gtest: $(GTEST_LIB)

$(GTEST_LIB):
	mkdir -p $(GTEST_BUILD_DIR) && \
	cd $(GTEST_BUILD_DIR) && \
	$(MAKE) -f ../make/Makefile CXXFLAGS="$(CXXFLAGS)" CFLAGS="$(CFLAGS)" CC=$(CC) CXX=$(CXX)

clean: 
	rm -f *.o msan_test
