//===-- asan_printf.cc ------------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file is a part of AddressSanitizer, an address sanity checker.
//
// Internal printf function, used inside ASan run-time library.
// We can't use libc printf because we intercept some of the functions used
// inside it.
//===----------------------------------------------------------------------===//

#include "asan_internal.h"
#include "asan_interceptors.h"

#include <stdarg.h>

namespace __asan {

void RawWrite(const char *buffer) {
  static const char *kRawWriteError = "RawWrite can't output requested buffer!";
  ssize_t length = (ssize_t)internal_strlen(buffer);
  if (length != asan_write(2, buffer, length)) {
    asan_write(2, kRawWriteError, internal_strlen(kRawWriteError));
    ASAN_DIE;
  }
}

static inline void AppendChar(char **buff, const char *buff_end, char c) {
  RAW_CHECK_MSG(*buff < buff_end, "Printf buffer overflow");
  **buff = c;
  (*buff)++;
}

// Appends number in a given base to buffer. If its length is less than
// "minimal_num_length", it is padded with leading zeroes.
static void AppendUnsigned(char **buff, const char *buff_end, uint64_t num,
                           uint8_t base, uint8_t minimal_num_length) {
  size_t const kMaxLen = 30;
  RAW_CHECK(base == 10 || base == 16);
  RAW_CHECK(minimal_num_length < kMaxLen);
  size_t num_buffer[kMaxLen];
  size_t pos = 0;
  do {
    RAW_CHECK_MSG(pos < kMaxLen, "appendNumber buffer overflow");
    num_buffer[pos++] = num % base;
    num /= base;
  } while (num > 0);
  while (pos < minimal_num_length) num_buffer[pos++] = 0;
  while (pos-- > 0) {
    size_t digit = num_buffer[pos];
    AppendChar(buff, buff_end, (digit < 10) ? '0' + digit
                                            : 'a' + digit - 10);
  }
}

static inline void AppendSignedDecimal(char **buff, const char *buff_end,
                                       int64_t num) {
  if (num < 0) {
    AppendChar(buff, buff_end, '-');
    num = -num;
  }
  AppendUnsigned(buff, buff_end, (uint64_t)num, 10, 0);
}

static inline void AppendString(char **buff, const char *buff_end,
                                const char *s) {
  // Avoid library functions like stpcpy here.
  RAW_CHECK(s);
  for (; *s; s++) {
    AppendChar(buff, buff_end, *s);
  }
}

static inline void AppendPointer(char **buff, const char *buff_end,
                                 uint64_t ptr_value) {
  AppendString(buff, buff_end, "0x");
  AppendUnsigned(buff, buff_end, ptr_value, 16, (__WORDSIZE == 64) ? 12 : 8);
}

static void VSNPrintf(char *buff, int buff_length,
                      const char *format, va_list args) {
  static const char *kPrintfFormatsHelp = "Supported Printf formats: "
                                          "%%[l]{d,u,x}; %%p; %%s";
  RAW_CHECK(format);
  const char *buff_end = &buff[buff_length - 1];
  const char *cur = format;
  for (; *cur; cur++) {
    if (*cur == '%') {
      cur++;
      bool have_l = (*cur == 'l');
      cur += have_l;
      int64_t dval;
      uint64_t uval, xval;
      switch (*cur) {
        case 'd': dval = have_l ? va_arg(args, intptr_t)
                                : va_arg(args, int);
                  AppendSignedDecimal(&buff, buff_end, dval);
                  break;
        case 'u': uval = have_l ? va_arg(args, uintptr_t)
                                : va_arg(args, unsigned int);
                  AppendUnsigned(&buff, buff_end, uval, 10, 0);
                  break;
        case 'x': xval = have_l ? va_arg(args, uintptr_t)
                                : va_arg(args, unsigned int);
                  AppendUnsigned(&buff, buff_end, xval, 16, 0);
                  break;
        case 'p': RAW_CHECK_MSG(!have_l, kPrintfFormatsHelp);
                  AppendPointer(&buff, buff_end, va_arg(args, uintptr_t));
                  break;
        case 's': RAW_CHECK_MSG(!have_l, kPrintfFormatsHelp);
                  AppendString(&buff, buff_end, va_arg(args, char*));
                  break;
        default:  RAW_CHECK_MSG(false, kPrintfFormatsHelp);
      }
    } else {
      AppendChar(&buff, buff_end, *cur);
    }
  }
  AppendChar(&buff, buff_end, '\0');
}

void VPrintf(const char *format, va_list args) {
  const int kLen = 1024 * 4;
  char buffer[kLen];
  VSNPrintf(buffer, kLen, format, args);
  RawWrite(buffer);
}

void Printf(const char *format, ...) {
  va_list args;
  va_start(args, format);
  VPrintf(format, args);
  va_end(args);
}

// Like Printf, but prints the current PID before the output string.
// TODO(glider): this should be done using a single RawWrite call. To do so,
// we'll need to make VSNPrintf return the number of characters.
void Report(const char *format, ...) {
  Printf("==%d== ", getpid());
  va_list args;
  va_start(args, format);
  VPrintf(format, args);
  va_end(args);
}

}  // namespace __asan
