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

TMPDIR="$(mktemp -d)"

# Build the app.
./gradlew build

# Create the output dir, removing if present.
rm -rf apks
mkdir -p apks

# Grab the new apks and move them to an intermediate directory.
cp `find ./app/build/outputs/apk/ -name *-release-unsigned.apk` $TMPDIR

# Align and sign the APKs.
APKS="$(ls $TMPDIR | sed 's/-unsigned.apk//')"
for apk in $APKS; do
  echo $f
  zipalign -v -p 4 $TMPDIR/$apk-unsigned.apk $TMPDIR/$apk-aligned.apk
  apksigner sign --ks $SIGNING_KEY --out apks/$apk.apk $TMPDIR/$apk-aligned.apk
done

rm -rf $TMPDIR
cd -
