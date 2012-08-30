#ifndef MSAN_INTERFACE_H
#define MSAN_INTERFACE_H
#include "sanitizer/common_interface_defs.h"

using __sanitizer::uptr;
using __sanitizer::sptr;

#ifdef __cplusplus
extern "C" {
#endif

void __msan_init();
void __msan_track_origins();
void __msan_warning();
void __msan_unpoison(void *a, uptr size);
void __msan_clear_and_unpoison(void *a, uptr size);
void __msan_memcpy_with_poison(void *dst, const void *src, uptr size);
void __msan_copy_poison(void *dst, const void *src, uptr size);
void __msan_move_poison(void *dst, const void *src, uptr size);
void __msan_poison(void *a, uptr size);

// Copy size bytes from src to dst and unpoison the result.
// Useful to implement unsafe loads.
void __msan_load_unpoisoned(void *src, uptr size, void *dst);

// Returns the offset of the first (at least partially) poisoned byte, or -1 if the whole range is good.
sptr __msan_test_shadow(const void *x, uptr size);

void __msan_clear_on_return();

// Default: -1 (don't exit on error).
void __msan_set_exit_code(int exit_code);

int __msan_set_poison_in_malloc(int do_poison);

// For testing.
void __msan_set_expect_umr(int expect_umr);
void __msan_break_optimization(void *x);
void __msan_print_shadow(const void *x, uptr size);
void __msan_print_param_shadow();
int  __msan_has_dynamic_component();

// Returns x such that %fs:x is the first byte of __msan_retval_tls.
int __msan_get_retval_tls_offset();
int __msan_get_param_tls_offset();

void __msan_partial_poison(void* data, void* shadow, uptr size);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif
