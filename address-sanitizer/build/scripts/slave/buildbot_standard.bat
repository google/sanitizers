@echo off

:: TODO(timurrrr) echo @@@BUILD_STEP clobber@@@

echo @@@BUILD_STEP update@@@
:: TODO(timurrrr)
::if [ "$BUILDBOT_CLOBBER" != "" ]; then
::  echo @@@BUILD_STEP clobber build@@@
::  rmdir /S /Q llvm || goto :DIE
::  rmdir /S /Q llvm-build || goto :DIE
::  mkdir llvm-build || goto :DIE
::fi

set REV_ARG=
if NOT "%BUILDBOT_REVISION%" == "" set REV_ARG="-r%BUILDBOT_REVISION%"

:: call -> because "svn" might be a batch script, ouch
call svn co http://llvm.org/svn/llvm-project/llvm/trunk llvm %REV_ARG% || goto :DIE
call svn co http://llvm.org/svn/llvm-project/cfe/trunk llvm/tools/clang %REV_ARG% || goto :DIE
call svn co http://llvm.org/svn/llvm-project/compiler-rt/trunk llvm/projects/compiler-rt %REV_ARG% || goto :DIE

set ROOT=%cd%

echo @@@BUILD_STEP cmake llvm@@@
mkdir llvm-build
cd llvm-build || goto :DIE
cmake -GNinja -DLLVM_ENABLE_ASSERTIONS=ON -DCMAKE_BUILD_TYPE=Release -DLLVM_TARGETS_TO_BUILD=X86 -DCOMPILER_RT_BUILD_SHARED_ASAN=ON ..\llvm || goto :DIE

echo @@@BUILD_STEP build compiler-rt@@@
:: Clean compiler-rt to get all the compile-time warnings,
:: then rebuild it separately before anything else to help us find ASan RTL
:: compile-time bugs quicker.
ninja -t clean compiler-rt
ninja compiler-rt

echo @@@BUILD_STEP build llvm@@@
ninja || goto :DIE

echo @@@BUILD_STEP run tests@@@
ninja check-asan check-sanitizer || goto :DIE

cd %ROOT%

:: TODO(timurrrr)
:: echo @@@BUILD_STEP build asan RTL with clang@@@

echo "ALL DONE"
goto :EOF

:DIE
:: TODO(timurrrr) : get the current process's PID?
taskkill /F /IM cl.exe /T 2>err
taskkill /F /IM clang.exe /T 2>err
taskkill /F /IM clang-cl.exe /T 2>err
taskkill /F /IM cmake.exe /T 2>err
taskkill /F /IM MSBuild.exe /T 2>err
taskkill /F /IM WerFault.exe /T 2>err
exit /b 42
