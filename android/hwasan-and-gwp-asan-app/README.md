# Sanitizer Test Android Apps

This repository currently contains a single test app. This app can be built for
either [HWASan](https://developer.android.com/ndk/guides/hwasan) or
[GWP-ASan](https://developer.android.com/ndk/guides/gwp-asan) usage.

Prebuilt apps can be found in the `prebuilt-apks` folder. These apps come fully
signed in two variants, a HWASan and a GWP-ASan version. They can be installed
onto your device by `adb install prebuilt-apks/app-<variant>-release.apk`.
Note: If you see errors along the lines of:
`Failure [INSTALL_FAILED_VERIFICATION_FAILURE: Package Verification Result]`,
you may need to `adb unroot` first. Once installed, the app will be visible
in your app drawer under the name "Sanitizer Test App".

To remove the app, you can:
 1. Long press the app in the app drawer, and drag it to the top right of the
    screen, into the "Uninstall" bin.
 2. Using `adb uninstall com.example.sanitizertest`

To build the app, simply `cd src && ./gradlew build`. This will build a debug
(unsigned) variant of the app for both HWASan and GWP-ASan, present under
`app/build/outputs/apk/gwpAsan/release/app-<variant>-debug-unsigned.apk`.
Installation instructions are the same as the prebuilts.

If your device policy doesn't allow for unsigned apps to be installed, you can
either use the prebuilt apps - or use the `build-and-sign.sh` script to build
and sign your own app. You will likely need to create your own signing
certificate, instructions are available in the script. Once the script runs,
signed APKs are available in `src/apks`.
