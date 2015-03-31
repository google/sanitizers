rm -rf chromium_libs && mkdir chromium_libs
cd asan-inst/lib64
cp libcrypt.so.* libc.so.* libresolv.so.* librt.so.* ../../chromium_libs
cd ../../chromium_libs
rm ../asan-glibc.zip
zip ../asan-glibc.zip *
cd ..
