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

# TODO(timurrrr): this file is an ugly hack.
# It assumes the build ASan/Win RTL is located in rtl/.

# Command to use:
# $ CLANG_BIN_PATH=... make CC=./build.sh CC_OUT=-o CFLAGS= POST_CFLAGS=
OBJ=$(echo "$2" | sed "s/exe/o/")
set -x
$CLANG_BIN_PATH/clang.exe -o $OBJ -c -faddress-sanitizer $3 && \
        link /nologo /debug $OBJ rtl\\asan_*.obj
