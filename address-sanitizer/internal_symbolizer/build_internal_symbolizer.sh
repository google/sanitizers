#!/bin/bash -exu

# Script to produce perfect, entirely self-contained symbolization library
# from libc++ and LLVM sources (and zlib, too). It internalizes symbols in these libs,
# so that this library may be linked into arbitrary programs and be invoked
# by Sanitizer runtime libraries to symbolize code/data in-process.
# The output of this script is a single-file archive which
# * includes a private copy of libc++, libz and some LLVM libs,
# * exports nothing except for the symbolizer interface,
# * has several libc functions redirected to sanitizer internal implementation,
#   adding a dependency on Sanitizer runtime library.

if [[ "$CLANG_DIR" == "" ||
      ! -x "${CLANG_DIR}/clang" ||
      ! -f "${CLANG_DIR}/../lib/LLVMgold.so" ]]; then
  echo "Missing or incomplete CLANG_DIR"
  exit 1
fi
if [[ "$LLVM_CHECKOUT" == "" ||
      ! -d "${LLVM_CHECKOUT}/projects/libcxxabi" ||
      ! -d "${LLVM_CHECKOUT}/projects/libcxx" ]]; then
  echo "Missing or incomplete LLVM_CHECKOUT"
  exit 1
fi
if [[ "$ZLIB_CHECKOUT" == ""  ||
      ! -x "${ZLIB_CHECKOUT}/configure" ||
      ! -f "${ZLIB_CHECKOUT}/zlib.h" ]]; then
  echo "Missing or incomplete ZLIB_CHECKOUT"
  exit 1
fi

CLANG=${CLANG_DIR}/clang
ROOT="$(cd "$(dirname "$0")" && pwd)"
LLVM_SYMBOLIZE_INTERFACE=${ROOT}/LLVMSymbolizeInterface.cpp

SCRATCH_DIR=$(mktemp -d)
J="${J:-8}"

COMMON_CFLAGS="-fPIC -flto -O2"

for BITS in 32 64; do
  # libc++abi can't be built without exceptions or rtti
  CXXABI_CFLAGS="${COMMON_CFLAGS} -m${BITS}"
  CFLAGS="${COMMON_CFLAGS} -m${BITS} -fno-exceptions -fno-rtti"
  LIBCXX_BUILD=${SCRATCH_DIR}/libcxx_build${BITS}
  LIBCXX_INST=${SCRATCH_DIR}/libcxx_inst${BITS}
  LLVM_BUILD=${SCRATCH_DIR}/llvm_build${BITS}
  SANITIZER_LLVM_BUILD=${SCRATCH_DIR}/sanitizer_llvm${BITS}
  ZLIB_BUILD=${SCRATCH_DIR}/zlib${BITS}

  # Build zlib.
  mkdir ${ZLIB_BUILD}
  cd ${ZLIB_BUILD}
  cp -r ${ZLIB_CHECKOUT}/* .
  CC=${CLANG} \
  CFLAGS=${CFLAGS} \
  ARFLAGS="rc --plugin ${CLANG_DIR}/../lib/LLVMgold.so" \
  RANLIB=/bin/true \
    ./configure --static
  make -j${J} libz.a

  # Build and install libcxxabi and libcxx.
  mkdir ${LIBCXX_BUILD}
  cd ${LIBCXX_BUILD}
  LLVM_BIN=${CLANG_DIR} LIBCXXABI_CFLAGS="${CXXABI_CFLAGS}" LIBCXX_CFLAGS="${CFLAGS} -D_LIBCPP_BUILD_STATIC" ${ROOT}/build_libcxx.sh ${LLVM_CHECKOUT}

  # From now on, use libraries we've just built. Disable exceptions as well.
  CFLAGS="${CFLAGS} -stdlib=libc++ -I${LIBCXX_BUILD}/include -L${LIBCXX_BUILD}/lib -I${ZLIB_BUILD} -L${ZLIB_BUILD} -fno-exceptions"

  # Test that clang works well with new libcxx. Compile the simple source:
  cd ${SCRATCH_DIR}
  echo -e "#include <cstdlib>\n int main() { return 0; }" > simple.cc
  ${CLANG}++ -v ${CFLAGS} simple.cc
  # And run it:
  ./a.out

  # Build LLVM with hacked libc++.
  mkdir ${LLVM_BUILD}
  cd ${LLVM_BUILD}
  # Mangle llvm namespace into "__sanitizer_llvm".
  CFLAGS="${CFLAGS} -Dllvm=__sanitizer_llvm"
  CC=${CLANG} CXX=${CLANG}++ cmake \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_FLAGS="${CFLAGS}" \
    -DCMAKE_CXX_FLAGS="${CFLAGS}" \
    -DLLVM_ENABLE_ZLIB=ON \
    -DLLVM_ENABLE_TERMINFO=OFF \
    ${LLVM_CHECKOUT}
  # Build necessary LLVM libraries.
  make LLVMSupport -j${J}
  make LLVMObject -j${J}
  make LLVMDebugInfo -j${J}

  # Copy LLVMSymbolize library bits, LLVM static libs, libc++ and libz to a separate
  # directory.
  cd ${SCRATCH_DIR}
  mkdir ${SANITIZER_LLVM_BUILD}
  cp ${LLVM_CHECKOUT}/tools/llvm-symbolizer/LLVMSymbolize.{h,cpp} \
     ${LLVM_SYMBOLIZE_INTERFACE} \
     ${LLVM_BUILD}/lib/libLLVM{DebugInfo,Object,Support}.a \
     ${LIBCXX_BUILD}/lib/libc++abi.a \
     ${LIBCXX_BUILD}/lib/libc++.a \
     ${ZLIB_BUILD}/libz.a \
     ${SANITIZER_LLVM_BUILD}

  # Compile additional C++ sources with -fPIC and optimization, and w/o RTTI.
  CFLAGS="${CFLAGS} -fPIC -fno-rtti -O2"
  cd ${SANITIZER_LLVM_BUILD}
  LLVM_CFLAGS="-I${LLVM_CHECKOUT}/include -I${LLVM_BUILD}/include -D__STDC_LIMIT_MACROS -D__STDC_CONSTANT_MACROS"
  ${CLANG}++ -v ${CFLAGS} ${LLVM_CFLAGS} ${ROOT}/SanitizerLibcWrapper.cpp -c -o SanitizerLibcWrapper.o
  ${CLANG}++ -v ${CFLAGS} ${LLVM_CFLAGS} LLVMSymbolize.cpp -c -o LLVMSymbolize.o
  ${CLANG}++ -v ${CFLAGS} ${LLVM_CFLAGS} LLVMSymbolizeInterface.cpp -c -o LLVMSymbolizeInterface.o

  # Merge LLVMSymbolize object files and other static LLVM libraries into a single object.
  for f in *.a; do
    members=$(ar t $f)
    # Make sure the names of extracted .o files are unique.
    for member in $members; do
      ar x $f $member
      mv $member $f.$member
    done
  done
  rm -f *.a

  SYMBOLIZER_API_LIST=__llvm_symbolize_set_demangling,__llvm_symbolize_code,__llvm_symbolize_data,__llvm_symbolize_flush,__llvm_symbolize_demangle

  # Merge all the object files together and copy the resulting library back.
  INTERNAL_SYMBOLIZER_LIBNAME=sanitizer_internal_symbolizer${BITS}.a
  ${CLANG_DIR}/llvm-link *.o -o all.bc
  ${CLANG_DIR}/opt -internalize -internalize-public-api-list=${SYMBOLIZER_API_LIST} all.bc -o opt.bc
  ${CLANG} opt.bc ${CFLAGS} -fno-lto -c -o opt.o
  ar rcs ${INTERNAL_SYMBOLIZER_LIBNAME} opt.o
done

echo ${SCRATCH_DIR}

echo "Success!"
