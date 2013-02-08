@echo off

:: TODO(timurrrr) echo @@@BUILD_STEP clobber@@@

echo @@@BUILD_STEP update@@@
:: TODO(timurrrr)
::if [ "$BUILDBOT_CLOBBER" != "" ]; then
::  echo @@@BUILD_STEP clobber build@@@
::  rmdir /S /Q llvm || goto :DIE
::  rmdir /S /Q llvm-build || goto :DIE
::  mkdir llvm-build || goto :DIE
::  rmdir /S /Q win_tests || goto :DIE
::fi

set REV_ARG=
if NOT "%BUILDBOT_REVISION%" == "" set REV_ARG="-r%BUILDBOT_REVISION%"

:: call -> because "svn" might be a batch script, ouch
call svn co http://llvm.org/svn/llvm-project/llvm/trunk llvm %REV_ARG% || goto :DIE
call svn co http://llvm.org/svn/llvm-project/cfe/trunk llvm/tools/clang %REV_ARG% || goto :DIE
call svn co http://llvm.org/svn/llvm-project/compiler-rt/trunk compiler-rt %REV_ARG% || goto :DIE
call svn co http://address-sanitizer.googlecode.com/svn/trunk/win/tests win_tests || goto :DIE

set ROOT=%cd%

echo @@@BUILD_STEP cmake llvm@@@
mkdir llvm-build
:: TODO(timurrrr): Is this enough to force a full re-configure?
del llvm-build\CMakeCache.txt
cd llvm-build
cmake ..\llvm || goto :DIE
echo @@@BUILD_STEP build llvm@@@
cmake --build . || goto :DIE
cd %ROOT%

:: TODO(timurrrr) echo @@@BUILD_STEP test llvm@@@

echo @@@BUILD_STEP build asan RTL@@@
set ASAN_PATH=compiler-rt\lib\asan
cd %ASAN_PATH% || goto :DIE
:: This only compiles, not links.
del *.pdb *.obj *.lib || goto :DIE

:: /MP <- parallel buidling (currently disabled)
:: /MT <- Multi-Threaded CRT with static linking
:: /Zi <- generate debug info
cl /nologo /MT /Zi /I.. /I../../include /c *.cc ../interception/*.cc ../sanitizer_common/*.cc || goto :DIE
lib /nologo /OUT:asan_rtl.lib *.obj || goto :DIE
cd %ROOT%

echo @@@BUILD_STEP asan test@@@
cd win_tests || goto :DIE
C:\cygwin\bin\make -s PLATFORM=Windows CC=../llvm-build/bin/Debug/clang++.exe FILECHECK=../llvm-build/bin/Debug/FileCheck.exe CFLAGS="-fsanitize=address -Xclang -cxx-abi -Xclang microsoft -g" EXTRA_OBJ=../compiler-rt/lib/asan/asan_rtl.lib -k || goto :DIE
cd %ROOT%

:: TODO(timurrrr) echo @@@BUILD_STEP asan test64@@@

:: TODO(timurrrr) echo @@@BUILD_STEP asan output_tests@@@

echo "ALL DONE"
goto :EOF

:DIE
exit /b %ERRORLEVEL%
