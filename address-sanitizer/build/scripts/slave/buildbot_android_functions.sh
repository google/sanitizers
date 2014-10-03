function build_llvm_symbolizer { # ARCH triple
    local _arch=$1
    local _triple=$2
    
    rm -rf llvm_build_android_$_arch
    mkdir llvm_build_android_$_arch
    cd llvm_build_android_$_arch

    local ANDROID_TOOLCHAIN=$ROOT/../../../android-ndk/standalone-$_arch
    local ANDROID_FLAGS="--target=$_triple --sysroot=$ANDROID_TOOLCHAIN/sysroot -B$ANDROID_TOOLCHAIN"
    cmake -GNinja \
        -DCMAKE_BUILD_TYPE=Release \
        -DLLVM_ENABLE_WERROR=OFF \
        -DCMAKE_C_COMPILER=$ROOT/llvm_build64/bin/clang \
        -DCMAKE_CXX_COMPILER=$ROOT/llvm_build64/bin/clang++ \
        -DCMAKE_C_FLAGS="$ANDROID_FLAGS" \
        -DCMAKE_CXX_FLAGS="$ANDROID_FLAGS" \
        -DANDROID=1 \
        -DLLVM_BUILD_RUNTIME=OFF \
        -DLLVM_TABLEGEN=$ROOT/llvm_build64/bin/llvm-tblgen \
        ${CMAKE_COMMON_OPTIONS} \
        $LLVM_CHECKOUT || echo @@@STEP_WARNINGS@@@
    ninja llvm-symbolizer || echo @@@STEP_WARNINGS@@@

    cd ..
}

function build_compiler_rt { # ARCH triple
    local _arch=$1
    local _triple=$2

    local ANDROID_TOOLCHAIN=$ROOT/../../../android-ndk/standalone-$_arch
    local ANDROID_LIBRARY_OUTPUT_DIR=$(ls -d $ROOT/llvm_build64/lib/clang/* | tail -1)
    local ANDROID_EXEC_OUTPUT_DIR=$ROOT/llvm_build64/bin
    local ANDROID_FLAGS="--target=$_triple --sysroot=$ANDROID_TOOLCHAIN/sysroot -B$ANDROID_TOOLCHAIN"

    # Always clobber android build tree.
    # It has a hidden dependency on clang (through CXX) which is not known to
    # the build system.
    rm -rf compiler_rt_build_android_$_arch
    mkdir compiler_rt_build_android_$_arch
    cd compiler_rt_build_android_$_arch

    cmake -GNinja -DCMAKE_BUILD_TYPE=$BUILD_TYPE \
        -DCMAKE_C_COMPILER=$ROOT/llvm_build64/bin/clang \
        -DCMAKE_CXX_COMPILER=$ROOT/llvm_build64/bin/clang++ \
        -DLLVM_CONFIG_PATH=$ROOT/llvm_build64/bin/llvm-config \
        -DCOMPILER_RT_INCLUDE_TESTS=ON \
        -DCOMPILER_RT_ENABLE_WERROR=ON \
        -DCMAKE_C_FLAGS="$ANDROID_FLAGS" \
        -DCMAKE_CXX_FLAGS="$ANDROID_FLAGS" \
        -DANDROID=1 \
        -DCOMPILER_RT_TEST_COMPILER_CFLAGS="$ANDROID_FLAGS" \
        -DCOMPILER_RT_TEST_TARGET_TRIPLE=arm-linux-androideabi \
        -DCOMPILER_RT_OUTPUT_DIR="$ANDROID_LIBRARY_OUTPUT_DIR" \
        -DCOMPILER_RT_EXEC_OUTPUT_DIR="$ANDROID_EXEC_OUTPUT_DIR" \
        ${CMAKE_COMMON_OPTIONS} \
        $LLVM_CHECKOUT/projects/compiler-rt || echo @@@STEP_WARNINGS@@@
    ninja asan || echo @@@STEP_WARNINGS@@@
    ls "$ANDROID_LIBRARY_OUTPUT_DIR"
    ninja AsanUnitTests SanitizerUnitTests || echo @@@STEP_WARNINGS@@@

    cd ..
}

function test_android { # ARCH emulator
    ANDROID_SDK=$ROOT/../../../android-sdk-linux/
    SYMBOLIZER_BIN=$ROOT/compiler_rt_build_android_arm/bin/llvm-symbolizer
    ADB=$ANDROID_SDK/platform-tools/adb
    DEVICE_ROOT=/data/local/asan_test

    echo @@@BUILD_STEP device setup@@@

    $ADB devices # should be empty
    $ANDROID_SDK/tools/emulator -avd arm-K -no-window -noaudio -no-boot-anim &
    sleep 10
    $ADB wait-for-device

    echo "Device is up"
    $ADB devices

    sleep 2

    $ADB push $SYMBOLIZER_BIN /system/bin/
    ADB=$ADB $ROOT/llvm_build64/bin/asan_device_setup
    sleep 2

    $ADB shell rm -rf $DEVICE_ROOT
    $ADB shell mkdir $DEVICE_ROOT

    echo @@@BUILD_STEP run asan lit tests [Android]@@@

    (cd $ANDROID_BUILD_DIR && ninja check-asan) || \
        echo @@@STEP_WARNINGS@@@

    echo @@@BUILD_STEP run sanitizer_common tests [Android]@@@

    $ADB push $ANDROID_BUILD_DIR/lib/sanitizer_common/tests/SanitizerTest $DEVICE_ROOT/

    $ADB shell "$DEVICE_ROOT/SanitizerTest; \
        echo \$? >$DEVICE_ROOT/error_code"
    $ADB pull $DEVICE_ROOT/error_code error_code && (exit `cat error_code`) || echo @@@STEP_WARNINGS@@@

    echo @@@BUILD_STEP run asan tests [Android]@@@

    $ADB push $ANDROID_BUILD_DIR/lib/asan/tests/AsanTest $DEVICE_ROOT/
    $ADB push $ANDROID_BUILD_DIR/lib/asan/tests/AsanNoinstTest $DEVICE_ROOT/

    NUM_SHARDS=7
    for ((SHARD=0; SHARD < $NUM_SHARDS; SHARD++)); do
        $ADB shell "ASAN_OPTIONS=start_deactivated=1 \
          GTEST_TOTAL_SHARDS=$NUM_SHARDS \
          GTEST_SHARD_INDEX=$SHARD \
          asanwrapper $DEVICE_ROOT/AsanTest; \
          echo \$? >$DEVICE_ROOT/error_code"
        $ADB pull $DEVICE_ROOT/error_code error_code && echo && (exit `cat error_code`) || echo @@@STEP_WARNINGS@@@
        $ADB shell " \
          GTEST_TOTAL_SHARDS=$NUM_SHARDS \
          GTEST_SHARD_INDEX=$SHARD \
          $DEVICE_ROOT/AsanNoinstTest; \
          echo \$? >$DEVICE_ROOT/error_code"
        $ADB pull $DEVICE_ROOT/error_code error_code && echo && (exit `cat error_code`) || echo @@@STEP_WARNINGS@@@
    done

    echo "Killing emulator"
    $ADB emu kill
    sleep 2

    $ADB devices
}

function android_emulator_cleanup {
    $ADB emu kill || true
}
