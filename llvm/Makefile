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

CXX=g++

TSAN=../third_party/tsan
ASAN=../asan
OPT=-O2

AddressSanitizer.so: AddressSanitizer.cpp Makefile
	$(CXX) -c $(OPT) -fPIC -g AddressSanitizer.cpp -o AddressSanitizer.o \
		-DASAN_USES_IGNORES=1 -D__STDC_LIMIT_MACROS -D__STDC_CONSTANT_MACROS -I$(TSAN) -I$(ASAN)
	$(CXX) -fPIC -shared -g $(TSAN)/ignore.cc $(TSAN)/common_util.cc AddressSanitizer.o -o AddressSanitizer.so

clean:
	rm -f *.o
	rm -f *.so
