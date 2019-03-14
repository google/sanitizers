# sanitizers
This project is the home for Sanitizers: AddressSanitizer, MemorySanitizer, ThreadSanitizer, LeakSanitizer, and more
The actual code resides in the [LLVM](http://llvm.org) repository.
Here we keep extended [documentation](../../wiki), [bugs](../../issues) and some helper code. 

The ocumentation for our tools:
* [AddressSanitizer](../../wiki/AddressSanitizer) (detects addressability issues) and [LeakSanitizer](../../wiki/AddressSanitizerLeakSanitizer) (detects memory leaks)
* ThreadSanitizer (detects data races and deadlocks) for [C++](../../wiki/ThreadSanitizerCppManual) and [Go](../../wiki/ThreadSanitizerGoManual)
* [MemorySanitizer](../../wiki/MemorySanitizer) (detects use of uninitialized memory)
* [HWASAN](https://clang.llvm.org/docs/HardwareAssistedAddressSanitizerDesign.html), or Hardware-assisted AddressSanitizer, a newer variant of AddressSanitizer that consumes much less memory
* [UBSan](https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html), or UndefinedBehaviorSanitizer

