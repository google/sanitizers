@echo off

:: TODO(timurrrr) echo @@@BUILD_STEP clobber@@@

echo @@@BUILD_STEP update@@@
:: TODO(timurrrr)
::if [ "$BUILDBOT_CLOBBER" != "" ]; then
::rmdir /S /Q asan
::fi

set REV_ARG=
if NOT "%BUILDBOT_REVISION%" == "" set REV_ARG="-r%BUILDBOT_REVISION%"

:: call -> because "svn" might be a batch script, ouch
call svn co http://llvm.org/svn/llvm-project/llvm/trunk llvm %REV_ARG% || goto :DIE
call svn co http://llvm.org/svn/llvm-project/cfe/trunk llvm/tools/clang %REV_ARG% || goto :DIE
call svn co http://llvm.org/svn/llvm-project/compiler-rt/trunk/lib/asan asan_rtl %REV_ARG% || goto :DIE
call svn co http://address-sanitizer.googlecode.com/svn/trunk/win/tests win_tests || goto :DIE

echo @@@BUILD_STEP build llvm@@@
rmdir /S /Q llvm-build
mkdir llvm-build || goto :DIE
cd llvm-build
:: TODO(timurrrr) make this incremental?
cmake ..\llvm || goto :DIE
devenv LLVM.sln /Build Debug /Project clang || goto :DIE
cd ..

:: TODO(timurrrr) echo @@@BUILD_STEP test llvm@@@

echo @@@BUILD_STEP build asan RTL@@@
cd asan_rtl
:: This only compiles, not links.
del *.obj || goto :DIE
cl /nologo /MP /Zi /c *.cc || goto :DIE
cd ..

echo @@@BUILD_STEP asan test@@@
cd win_tests
C:\cygwin\bin\make PLATFORM=Windows CC=../llvm-build/bin/Debug/clang.exe CC_OUT="-c -o" CFLAGS=-faddress-sanitizer EXTRA_OBJ=../asan_rtl/*.obj || goto :DIE
cd ..

:: TODO(timurrrr) echo @@@BUILD_STEP asan test64@@@

:: TODO(timurrrr) echo @@@BUILD_STEP asan output_tests@@@

echo "ALL DONE"
goto :EOF

:DIE
exit /b %ERRORLEVEL%
