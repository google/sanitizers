@echo off

:: TODO(timurrrr) echo @@@BUILD_STEP clobber@@@

echo @@@BUILD_STEP update@@@
:: TODO(timurrrr)
::if [ "$BUILDBOT_CLOBBER" != "" ]; then
rmdir /S /Q asan
::fi

set REV_ARG=
if NOT "%BUILDBOT_REVISION%" == "" set REV_ARG="-r%BUILDBOT_REVISION%"

:: TODO(timurrrr): checkout more

:: call -> because "svn" might be a batch script, ouch
call svn checkout http://llvm.org/svn/llvm-project/compiler-rt/trunk/lib/asan asan %REV_ARG%
cd asan

:: TODO(timurrrr) echo @@@BUILD_STEP build llvm@@@

:: TODO(timurrrr) echo @@@BUILD_STEP test llvm@@@

echo @@@BUILD_STEP build asan@@@
:: TODO(timurrrr): this only tests that this compiles, not links.
cl /nologo /Zi /c *.cc

:: TODO(timurrrr) echo @@@BUILD_STEP asan test32@@@

:: TODO(timurrrr) echo @@@BUILD_STEP asan test64@@@

:: TODO(timurrrr) echo @@@BUILD_STEP asan output_tests@@@
