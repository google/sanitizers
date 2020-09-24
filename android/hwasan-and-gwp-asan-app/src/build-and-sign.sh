#!/bin/bash -e

# Script to build all variants of the app, and start the signing process. The
# signing key is not part of the public repository. You can create your own
# signing key by following the instructions:
#  - https://developer.android.com/studio/build/building-cmdline#sign_cmdline
#
#  tl;dr >> $ keytool -genkey -v -keystore my-release-key.jks -keyalg RSA \
#             -keysize 2048 -validity 10000 -alias my-alias
#
# To learn more about the process of building APKs using the command line, see:
#  - https://developer.android.com/studio/build/building-cmdline

SIGNING_KEY=my-release-key.jks

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd $DIR

# Build the app.
./gradlew build

# Clean up the intermediate and output directories.
rm -f apks \
      /tmp/app-gwpAsan-release-unsigned.apk \
      /tmp/app-hwasan-release-unsigned.apk \
      /tmp/app-gwpAsan-release-unsigned-aligned.apk \
      /tmp/app-hwasan-release-unsigned-aligned.apk

# Grab the new apks and move them to an intermediate directory.
cp ./app/build/outputs/apk/gwpAsan/release/app-gwpAsan-release-unsigned.apk /tmp/
cp ./app/build/outputs/apk/hwasan/release/app-hwasan-release-unsigned.apk /tmp/

# Align the APKs for signing.
zipalign -v -p 4 /tmp/app-gwpAsan-release-unsigned.apk \
  /tmp/app-gwpAsan-release-unsigned-aligned.apk
zipalign -v -p 4 /tmp/app-hwasan-release-unsigned.apk \
  /tmp/app-hwasan-release-unsigned-aligned.apk

# And finally - sign the APKs using our key.
mkdir -p apks
apksigner sign --ks $SIGNING_KEY --out apks/app-gwpAsan-release.apk \
  /tmp/app-gwpAsan-release-unsigned-aligned.apk
apksigner sign --ks $SIGNING_KEY --out apks/app-hwasan-release.apk \
  /tmp/app-hwasan-release-unsigned-aligned.apk

cd -
