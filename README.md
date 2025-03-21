# sanitizers (Archived)

**This project has been archived and is no longer actively maintained.**

The Sanitizers project, which includes AddressSanitizer, MemorySanitizer, ThreadSanitizer, LeakSanitizer, and more, is now archived. The core code for these sanitizers resides within the [LLVM](http://llvm.org) repository. This repository will be retained for archival purposes, providing access to historical documentation, bugfixes, and helper code.

**Important:** Please do not file new bug reports in this repository.

**Where to Report Bugs:**

* **LLVM:** For bugs related to the sanitizer runtimes and instrumentation, please report them to the [LLVM Bug Tracker]([https://bugs.llvm.org/](https://github.com/llvm/llvm-project/issues/)).
* **GCC:** For bugs related to the GCC port of the sanitizers, please report them to the [GCC Bugzilla](https://gcc.gnu.org/bugzilla/).
* **Linux Kernel:** For bugs related to Kernel AddressSanitizer (KASAN), Kernel MemorySanitizer (KMSAN), or Kernel ConcurrencySanitizer (KCSAN), please report them through the appropriate Linux kernel bug reporting channels, such as the [Linux kernel mailing list](https://vger.kernel.org/vger-lists.html#linux-kernel).
* **Linux Distributions:** For bugs related to compiler issues in specific Linux distributions that are not reproducible in trunk compilers, please report them to the respective distribution's bug tracker (e.g., Debian Bug Tracking System, Red Hat Bugzilla).
* **Apple and Microsoft:** For bugs related to the compilers provided by Apple (Xcode) or Microsoft (Visual Studio), please report them through the respective vendor's bug reporting channels.

**Documentation (Archived):**

* [AddressSanitizer](../../wiki/AddressSanitizer) (detects addressability issues) and [LeakSanitizer](../../wiki/AddressSanitizerLeakSanitizer) (detects memory leaks)
* ThreadSanitizer (detects data races and deadlocks) for [C++](../../wiki/ThreadSanitizerCppManual) and [Go](../../wiki/ThreadSanitizerGoManual)
* [MemorySanitizer](../../wiki/MemorySanitizer) (detects use of uninitialized memory)
* [HWASAN](https://clang.llvm.org/docs/HardwareAssistedAddressSanitizerDesign.html), or Hardware-assisted AddressSanitizer, a newer variant of AddressSanitizer that consumes much less memory
* [UBSan](https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html), or UndefinedBehaviorSanitizer

**Kernel Sanitizers (Archived Documentation):**

* [KASAN](https://www.kernel.org/doc/html/v4.12/dev-tools/kasan.html)
* [KMSAN](https://github.com/google/kmsan)
* [KCSAN](https://github.com/google/kernel-sanitizers/blob/master/KCSAN.md)

Thank you for your understanding.
