function test_android {
    ANDROID_SDK=$ROOT/../../../android-sdk-linux/
    SYMBOLIZER_BIN=$ROOT/../../../llvm-symbolizer
    ADB=$ANDROID_SDK/platform-tools/adb
    DEVICE_ROOT=/data/local/asan_test

    echo @@@BUILD_STEP device setup@@@

    $ADB devices # should be empty
    $ANDROID_SDK/tools/emulator -avd arm-K -no-window -noaudio -no-boot-anim
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
        echo @@@STEP_FAILURE@@@

    echo @@@BUILD_STEP run sanitizer_common tests [Android]@@@

    $ADB push $ANDROID_BUILD_DIR/lib/sanitizer_common/tests/SanitizerTest $DEVICE_ROOT/

    $ADB shell "$DEVICE_ROOT/SanitizerTest; \
        echo \$? >$DEVICE_ROOT/error_code"
    $ADB pull $DEVICE_ROOT/error_code error_code && (exit `cat error_code`) || echo @@@STEP_FAILURE@@@

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
        $ADB pull $DEVICE_ROOT/error_code error_code && echo && (exit `cat error_code`) || echo @@@STEP_FAILURE@@@
        $ADB shell " \
          GTEST_TOTAL_SHARDS=$NUM_SHARDS \
          GTEST_SHARD_INDEX=$SHARD \
          $DEVICE_ROOT/AsanNoinstTest; \
          echo \$? >$DEVICE_ROOT/error_code"
        $ADB pull $DEVICE_ROOT/error_code error_code && echo && (exit `cat error_code`) || echo @@@STEP_FAILURE@@@
    done

    echo "Killing emulator"
    $ADB emu kill
    sleep 2

    $ADB devices
}
