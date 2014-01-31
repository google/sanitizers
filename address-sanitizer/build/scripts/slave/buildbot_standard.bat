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
call svn co http://llvm.org/svn/llvm-project/compiler-rt/trunk llvm/projects/compiler-rt %REV_ARG% || goto :DIE
call svn co http://address-sanitizer.googlecode.com/svn/trunk/win/tests win_tests || echo "Failed to update Windows tests, alas..."

set ROOT=%cd%

echo @@@BUILD_STEP build asan RTL@@@
:: Build the RTL manually - useful to detect RTL build errors early.
set ASAN_PATH=llvm\projects\compiler-rt\lib\asan
cd %ASAN_PATH% || goto :DIE
del *.pdb *.o *.obj *.lib || goto :DIE

:: /WX <- treat warnings as errors
:: /W3 <- warnings level 3
:: /MP <- parallel buidling (currently disabled)
:: /MT <- Multi-Threaded CRT with static linking
:: /Zi <- generate debug info
cl /nologo /WX /W3 /MT /Zi /I.. /I../../include /c *.cc ../interception/*.cc ../sanitizer_common/*.cc || goto :DIE
lib /nologo /ignore:4221 /OUT:asan_rtl.lib *.obj || goto :DIE
cl /nologo /WX /W3 /MT /Zi /DASAN_DLL_THUNK /c asan_dll_thunk.cc || goto :DIE
lib /nologo /ignore:4221 /OUT:asan_dll_thunk.lib asan_dll_thunk.obj
cd %ROOT%

echo @@@BUILD_STEP cmake llvm@@@
mkdir llvm-build
cd llvm-build || goto :DIE

:: TODO(timurrrr): Is this enough to force a full re-configure?
del CMakeCache.txt
rmdir /S /Q CMakeFiles

cmake -GNinja -DLLVM_ENABLE_ASSERTIONS=ON -DCMAKE_BUILD_TYPE=Release -DLLVM_TARGETS_TO_BUILD=X86 ..\llvm || goto :DIE
echo @@@BUILD_STEP build llvm@@@
ninja || goto :DIE
:: TODO(timurrrr): Run ninja second time to work around
:: http://public.kitware.com/Bug/view.php?id=14167
ninja || goto :DIE
cd %ROOT%

:: TODO(timurrrr) echo @@@BUILD_STEP test llvm@@@

echo @@@BUILD_STEP asan test@@@
cd win_tests || goto :DIE
C:\cygwin\bin\make -s PLATFORM=Windows RM_F="/cygdrive/c/cygwin/bin/rm -f" clean || goto :DIE
C:\cygwin\bin\make -s PLATFORM=Windows CC=../llvm-build/bin/clang-cl FILECHECK=../llvm-build/bin/FileCheck CFLAGS="-fsanitize=address -Xclang -g" UAR_FLAG="-fsanitize=use-after-return" -k || goto :DIE

echo @@@BUILD_STEP asan DLL thunk test@@@
cd dll_tests || goto :DIE
C:\cygwin\bin\make -s PLATFORM=Windows RM_F="/cygdrive/c/cygwin/bin/rm -f" clean || goto :DIE
C:\cygwin\bin\make -s PLATFORM=Windows CC=../../llvm-build/bin/clang-cl FILECHECK=../../llvm-build/bin/FileCheck CFLAGS="-fsanitize=address -Xclang -g" -k || goto :DIE
cd %ROOT%

:: TODO(timurrrr) echo @@@BUILD_STEP asan test64@@@

:: TODO(timurrrr): Re-enable once http://llvm.org/PR17098 is fixed
:: echo @@@BUILD_STEP build asan RTL with clang@@@
:: cd %ASAN_PATH% || goto :DIE
:: %ROOT%\llvm-build\bin\clang-cl /GR- /I.. /I../../include /c *.cc ..\interception\*.cc ..\sanitizer_common\*.cc || goto :DIE
:: cd %ROOT%

echo "ALL DONE"
goto :EOF

:DIE
:: TODO(timurrrr) : get the current process's PID?
taskkill /F /IM cmake.exe /T 2>err
taskkill /F /IM MSBuild.exe /T 2>err
exit /b 42
