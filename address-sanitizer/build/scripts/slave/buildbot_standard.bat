@echo off

:: TODO(timurrrr) echo @@@BUILD_STEP clobber@@@

echo @@@BUILD_STEP update@@@
:: TODO(timurrrr)
::if [ "$BUILDBOT_CLOBBER" != "" ]; then
::  echo @@@BUILD_STEP clobber build@@@
::  rmdir /S /Q asan_rtl || goto :DIE
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
call svn co http://llvm.org/svn/llvm-project/compiler-rt/trunk/lib/asan asan_rtl %REV_ARG% || goto :DIE
call svn co http://address-sanitizer.googlecode.com/svn/trunk/win/tests win_tests || goto :DIE

mkdir llvm-build

echo @@@BUILD_STEP cmake llvm@@@
:: TODO(timurrrr): Is this enough to force a full re-configure?
del llvm-build\CMakeCache.txt
cd llvm-build
cmake ..\llvm || goto :DIE
echo @@@BUILD_STEP build llvm@@@
devenv LLVM.sln /Build Debug /Project clang || goto :DIE
cd ..

:: TODO(timurrrr) echo @@@BUILD_STEP test llvm@@@

echo @@@BUILD_STEP build asan RTL@@@
cd asan_rtl
:: This only compiles, not links.
del *.pdb *.obj *.lib || goto :DIE

:: /MP <- parallel buidling
:: /MD\/MT <- Multi-Threaded CRT with dynamic\static linking
:: /Zi <- generate debug info
:: /D_CRTIMP="" <- cut off the __declspec(dllimport) from malloc & friends
cl /nologo /MP /MT /Zi /c *.cc interception/*.cc || goto :DIE
lib /nologo /OUT:asan_rtl.lib *.obj || goto :DIE
cd ..

echo @@@BUILD_STEP asan test@@@
cd win_tests
C:\cygwin\bin\make PLATFORM=Windows CC=../llvm-build/bin/Debug/clang.exe CFLAGS="-faddress-sanitizer -g" EXTRA_OBJ=../asan_rtl/asan_rtl.lib || goto :DIE
cd ..

:: TODO(timurrrr) echo @@@BUILD_STEP asan test64@@@

:: TODO(timurrrr) echo @@@BUILD_STEP asan output_tests@@@

echo "ALL DONE"
goto :EOF

:DIE
exit /b %ERRORLEVEL%
