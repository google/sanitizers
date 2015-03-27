/* Trick the outdated ASan instrumentation in glibc into thinking that we're
 * linking against an equally outdated ASan runtime. The up-to-date runtime is
 * ABI-compatible with old instrumentation as long as UAR detection is not used
 * (which we disable at compile time for glibc).
 * This is needed until ASan v5 is merged into gcc.
 */

void __asan_init_v5();

void __asan_init_v4() {
  __asan_init_v5();
}
