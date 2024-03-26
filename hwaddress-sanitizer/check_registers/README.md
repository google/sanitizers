# check_registers - tests for x86 address tagging support in various registers

## Overview

`check_registers` is a test suite that evaluates the capabilities of a x86 CPU
with hardware pointer tagging support (e.g. Intel LAM or AMD UAI). It consists
of a number of assembly functions that check the behavior of different
instructions in the presence of tagged pointers.

`check_registers` is meant to be run on a x86 host that has a CPU with hardware
pointer tagging support (e.g. Intel LAM or AMD UAI) and a kernel with the
pointer tagging API:
 - `arch_prctl(ARCH_GET_MAX_TAG_BITS, &tag_bits)`
 - `arch_prctl(ARCH_ENABLE_TAGGED_ADDR, tag_bits)`
 - `arch_prctl(ARCH_GET_UNTAG_MASK, &tag_mask)`

As of March 2023, this API exists as a set of downstream kernel patches
available at
https://lore.kernel.org/lkml/20230123220500.21077-1-kirill.shutemov@linux.intel.com/

## Building

```
  $ g++ check_registers.cc -o check_registers
```

## Running

```
  $ ./check_registers [notag] [expect] [list of testcases]
```

By default, `./check_registers` runs all tests, passing tagged pointers to them
and printing the results to stdout. If the host does not support pointer
tagging, all tests will fail:

```
  $ ./check_registers 
  Pointer tagging not supported, proceeding without it.
  call_cs_rax: FAIL
  jump_cs_rax: FAIL
  mov_cs_rax: FAIL
  ...
```

Running `./check_registers notag` will pass untagged pointers to tests, so they
will pass:

```
  $ ./check_registers notag
  Pointer tagging not supported, proceeding without it.
  call_cs_rax: PASS
  jump_cs_rax: PASS
  mov_cs_rax: PASS
```

Running `./check_registers` on a tagging-enabled host will produce a mix of
passing and failing tests. To check which tests are expected to pass or fail,
run `./check_registers expect`:

```
  $ ./check_registers expect
  Pointer tagging not supported, proceeding without it.
  call_cs_rax: FAIL (expected)
  jump_cs_rax: FAIL (expected)
  mov_cs_rax: FAIL (unexpected)
```

One can also pass the list of individual test cases to `check_registers`:

```
  $ ./check_registers ret_cs
  Pointer tagging not supported, proceeding without it.
  ret_cs: FAIL
```

## Test cases

Most test case names consist of three parts: operation, segment register prefix
and register name. One exception is `ret_cs`, which does not have register
inputs and is using an implicit CS: segment prefix.

There are three data flow test groups, which are expected to pass on a
tagging-enabled host:
 - `mov_$seg_$reg` - performs `movq $seg:(%$reg), %rbx`,
 - `movaps_$seg_$reg` - performs `movaps $seg:(%$reg), %xmm0`,
 - `tls_fs_$reg` -   performs `movq fs:(%$reg)`.

, and three control flow test groups, which are expected to fail:
 - `call_cs_$reg` - performs `callq *%$reg` (`$reg` cannot be `%rsp`),
 - `jump_cs_$reg` - performs `jmpq *%$reg`,
 - `ret_cs`       - performs `ret`.

For the data flow tests the address in `$reg` is tagged (is in the
non-canonical form). `mov` and `movaps` tests accept userspace pointers
with bits 57:58 set to 1. `tls` tests accept negative offsets with bits
57 and 58 set to 0. `mov` and `movaps` tests also support different segment
prefixes, which should not affect the test result.

Control flow tests accept a tagged pointer to executable code that is passed via
a general purpose register (for `call` and `jump`) or is stored on the top of
the stack (for `ret`). The corresponding instructions do not support segment
prefixes.

## Debugging

To run an individual test under `gdb`, e.g. `movaps_cs_rcx`:

```
  $ gdb ./check_registers
  (gdb) set follow-fork-mode child
  (gdb) br _Z13movaps_cs_rcxPv
  (gdb) r movaps_cs_rcx
  ...
  Thread 2.1 "check_registers" hit Breakpoint 1, 0x0000555555557824 in movaps_cs_rcx(void*) ()
```

To figure out the name of a function corresponding to the particular test, check
the source or the output of `nm check_registers`.
