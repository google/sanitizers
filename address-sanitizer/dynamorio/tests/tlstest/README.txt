Building:
   clang -fno-omit-frame-pointer -fPIC -shared -O2 lib.c -o lib.so
   clang -fsanitize=address main.c lib.so -Wl,-rpath=`pwd`
