#ifndef MSAN_INTERFACE_H
#define MSAN_INTERFACE_H
typedef long uptr;
typedef unsigned long long u64;
extern "C" {
void __msan_init();
void __msan_warning();
void __msan_unpoison(void *a, uptr size);
void __msan_copy_poison(void *dst, void *src, uptr size);
void __msan_poison(void *a, uptr size);

void __msan_clear_on_return();

// Default: -1 (don't exit on error).
void __msan_set_exit_code(int exit_code);

int __msan_set_poison_in_malloc(int do_poison);

// For testing.
void __msan_set_expect_umr(int expect_umr);
void __msan_break_optimization(void *x);
void __msan_print_shadow(void *x, int size);
void __msan_print_param_shadow();
int  __msan_has_dynamic_component();


}  // extern "C"
#endif
