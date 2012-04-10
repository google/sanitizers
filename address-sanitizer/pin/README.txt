Experimental PIN-ASAN plugin --
allows to find heap-related bugs in the code which we do not
instrument with clang (e.g. system libraries).
Don't expect anything here to *really work*.

Building:
 1. Download PIN from pintool.org
   (I used pin-2.10-45467-gcc.3.4.6-ia32_intel64-linux)
 2. Place asan_pin.cc into source/tools/SimpleExamples directory.
 3. Modify 'makefile': add asan_pin to TOOL_ROOTS and TEST_TOOLS_ROOTS.
 4. Type 'make'

Running:
 1. Build a small example:
   clang -fno-omit-frame-pointer -fPIC -shared -O2 pintest_so.c -o pintest_so.so
   clang -faddress-sanitizer pintest_main.c pintest_so.so -Wl,-rpath=`pwd`
 2. Run it, the error will not be detected:
   % ./a.out
 3. Run it with the pin tool, the error should be detected:
   (from the source/tools/SimpleExamples directory)
   % ../../../pin -t obj-intel64/asan_pin.so -- ../../../../a.out
   ...
   ==13070== ERROR: AddressSanitizer heap-buffer-overflow ...



