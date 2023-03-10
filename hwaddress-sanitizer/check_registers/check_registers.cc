// check_registers: tests for x86 address tagging support in various registers.

// Each test is an assembly function that takes an address and attempts to
// access it using the chosen instruction, register and segment prefix.
// Because such accesses may result in page faults, these functions are executed
// in separate subprocesses, and a test failure is reported if the subprocess
// dies from a signal.
//
// Usage:
//
//  ./check_registers [notag] [expect] [list of testcases]
//
// By default, the program runs all the tests with tagging enabled and without
// printing the test expectations. Extra arguments are:
//  - notag: pass non-tagged pointers to the functions (all tests must pass);
//  - expect: print tags expectations for the case tagging is enabled;
//  - list of testcases: a space-separated list of tests to run.
//
// There currently are 6 types of test cases in two groups.
// Data flow tests (expected to PASS with tagging enabled):
//  - mov_$seg_$reg - performs 'movq $seg:(%$reg), %rbx',
//  - movaps_$seg_$reg - performs 'movaps $seg:(%$reg), %xmm0',
//  - tls_fs_$reg -   performs 'movq fs:(%$reg)'.
//
//  For these tests the address in $reg is tagged (is in the non-canonical
//  form). "mov" and "movaps" tests accept userspace pointers with bits 57:58
//  set to 1. "tls" tests accept negative offsets with bits 57 and 58 set to 0.
//  "mov" and "movaps" tests also support different segment prefixes, which
//  should not affect the test result.
//
// Control flow tests (expected to FAIL with tagging enabled):
//  - call_cs_$reg - performs 'callq *%$reg' ($reg cannot be %rsp),
//  - jump_cs_$reg - performs 'jmpq *%$reg',
//  - ret_cs      - performs 'ret'.
//
//  These tests accept a tagged pointer to executable code that is passed via
//  a general purpose register (for "call" and "jump") or is stored on the top
//  of the stack (for "ret"). The corresponding instructions do not support
//  segment prefixes.

#include <asm/prctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <cstdio>
#include <iostream>
#include <set>
#include <string>

#define ARCH_GET_UNTAG_MASK 0x4001
#define ARCH_ENABLE_TAGGED_ADDR 0x4002
#define ARCH_GET_MAX_TAG_BITS 0x4003

#define arch_prctl(...) syscall(__NR_arch_prctl, __VA_ARGS__)

// Allocate some TLS for fs: accesses.
__thread int ti[1024];

int tag_bits;
uint64_t tag_mask;
void *tagged_addr, *tagged_offset, *tagged_jump;

// Try to enable memory tagging for the process. Depending on @force, in the
// case of a failure, either proceed without tags or bail out.
bool try_enable_tagging(bool force) {
  int err = arch_prctl(ARCH_GET_MAX_TAG_BITS, &tag_bits, 0, 0, 0);
  if (err) {
    if (!force) return false;
    std::perror(__FUNCTION__);
    exit(EXIT_FAILURE);
  }

  tag_bits = std::min(tag_bits, 6);
  int ret = arch_prctl(ARCH_ENABLE_TAGGED_ADDR, tag_bits, 0, 0, 0);

  if (ret) {
    if (!force) return false;
    std::perror(__FUNCTION__);
    exit(EXIT_FAILURE);
  }

  ret = arch_prctl(ARCH_GET_UNTAG_MASK, &tag_mask, 0, 0, 0);

  if (ret) {
    if (!force) return false;
    std::perror(__FUNCTION__);
    exit(EXIT_FAILURE);
  }

  std::cout << "Successfully enabled memory tagging.\n";
  std::cout << "  Tag bits: " << tag_bits << "\n";
  std::cout << "  Tag mask: " << (void *)tag_mask << "\n";
  return true;
}

#define TEST_FN_NAME(prefix, seg, reg) prefix##_##seg##_##reg
#define TEST_STR_NAME(prefix, seg, reg) #prefix "_" #seg "_" #reg

//
// Helper function for the "ret_cs" test that pushes the tagged argument to the
// stack and returns to it.
///
static void ret_cs(void *addr) {
  asm volatile(
      "push %0\n"
      "ret\n"
      :
      : "r"(addr));
}

// Helper function for mov_$seg_$reg and tls_$seg_$reg:
//  - save $reg (exchange it with %rax);
//  - load tagged argument into $reg;
//  - move $seg:($reg) to %rbx;
//  - restore $reg.
#define FN_LOAD_SEG_REG(seg_name, reg_name)                \
  void TEST_FN_NAME(mov, seg_name, reg_name)(void *addr) { \
    asm volatile("xchg %%rax, %%" #reg_name                \
                 "\n"                                      \
                 "movq %0, %%" #reg_name                   \
                 "\n"                                      \
                 "movq %%" #seg_name ":(%%" #reg_name      \
                 "), %%rbx\n"                              \
                 "xchg %%rax, %%" #reg_name "\n"           \
                 : /* no outputs */                        \
                 : "r"(addr)                               \
                 : "rax", "rbx");                          \
  }

// Helper function for movaps_$seg_$reg:
//  - save $reg (exchange it with %rax);
//  - load tagged argument into $reg;
//  - movaps $seg:($reg) to %xmm0;
//  - restore $reg.
#define FN_MOVAPS_SEG_REG(seg_name, reg_name)                 \
  void TEST_FN_NAME(movaps, seg_name, reg_name)(void *addr) { \
    asm volatile("xchg %%rax, %%" #reg_name                   \
                 "\n"                                         \
                 "movq %0, %%" #reg_name                      \
                 "\n"                                         \
                 "movaps %%" #seg_name ":(%%" #reg_name       \
                 "), %%xmm0\n"                                \
                 "xchg %%rax, %%" #reg_name "\n"              \
                 : /* no outputs */                           \
                 : "r"(addr)                                  \
                 : "rax");                                    \
  }

// Helper function for jmp_cs_$reg:
//  - load tagged argument into $reg;
//  - jmpq *$reg
//
// The jump target is supposed to terminate the process, so we do not care about
// clobbering the registers.
#define FN_JUMP_REG(reg_name)                                \
  static void TEST_FN_NAME(jump, cs, reg_name)(void *addr) { \
    asm volatile("movq %0, %%" #reg_name                     \
                 "\n"                                        \
                 "jmpq *%%" #reg_name "\n" /* no outputs */  \
                 :                                           \
                 : "r"(addr)                                 \
                 :);                                         \
  }

// Helper function for call_cs_$reg:
//  - load tagged argument into $reg;
//  - callq *$reg
//
// The call target is supposed to terminate the process, so we do not care about
// clobbering the registers.
// Note that $reg cannot be %rsp, because in that case the target must be both
// writable and executable.
#define FN_CALL_REG(reg_name)                                \
  static void TEST_FN_NAME(call, cs, reg_name)(void *addr) { \
    asm volatile("movq %0, %%" #reg_name                     \
                 "\n"                                        \
                 "callq *%%" #reg_name "\n" /* no outputs */ \
                 :                                           \
                 : "r"(addr)                                 \
                 :);                                         \
  }

// Generate test functions for "mov" and "movaps" tests.
#define FN_TEST_SEG_REG(seg, reg) \
  FN_LOAD_SEG_REG(seg, reg)       \
  FN_MOVAPS_SEG_REG(seg, reg)

// Generate test functions for a particular GP register.
#define FN_TEST_REG_NOCALL(reg) \
  FN_TEST_SEG_REG(cs, reg)      \
  FN_TEST_SEG_REG(ds, reg)      \
  FN_TEST_SEG_REG(es, reg)      \
  FN_TEST_SEG_REG(fs, reg)      \
  FN_TEST_SEG_REG(gs, reg)      \
  FN_TEST_SEG_REG(ss, reg)      \
  FN_JUMP_REG(reg)

#define FN_TEST_REG(reg)  \
  FN_TEST_REG_NOCALL(reg) \
  FN_CALL_REG(reg)

// Generate test functions for all GP registers.
FN_TEST_REG(rax)
FN_TEST_REG(rbx)
FN_TEST_REG(rcx)
FN_TEST_REG(rdx)
FN_TEST_REG(rdi)
FN_TEST_REG(rsi)
FN_TEST_REG_NOCALL(rsp)
FN_TEST_REG(rbp)

typedef void (*test_f)(void *);

enum TestType {
  CS_JMP,        // jmp to memory, no segment prefix, assuming CS
  CS_RET,        // ret to memory at *RSP, no explicit segment or register
  NOFS_MEM_PTR,  // any segment register except FS, memory pointer
  FS_MEM_PTR,    // fs:reg access to memory pointer, FS set to 0
  FS_OFFSET,  // fs:reg access to TLS (reg contains negative offset), FS remains
              //   intact
};

struct Test {
  const char *name;
  test_f fn;
  TestType type;
  bool expect;
};

// Declare a test named "$prefix_$seg_$reg" that will call the $op_$seg_$reg()
// helper function.
#define TEST_SEG_REG(prefix, op, seg, reg, test_type, test_expect)             \
  {                                                                            \
    .name = TEST_STR_NAME(prefix, seg, reg), .fn = TEST_FN_NAME(op, seg, reg), \
    .type = test_type, .expect = test_expect                                   \
  }

// Test cases for a particular segment:register pair.
#define TEST_MEM_SEG_REG(seg, reg, test_type)        \
  TEST_SEG_REG(mov, mov, seg, reg, test_type, true), \
      TEST_SEG_REG(movaps, movaps, seg, reg, test_type, true)

// All test cases for a particular GP register.
#define TEST_REG_NOCALL(reg)                            \
  TEST_SEG_REG(jump, jump, cs, reg, CS_JMP, false),     \
      TEST_MEM_SEG_REG(cs, reg, NOFS_MEM_PTR),          \
      TEST_MEM_SEG_REG(ds, reg, NOFS_MEM_PTR),          \
      TEST_MEM_SEG_REG(es, reg, NOFS_MEM_PTR),          \
      TEST_MEM_SEG_REG(fs, reg, FS_MEM_PTR),            \
      TEST_SEG_REG(tls, mov, fs, reg, FS_OFFSET, true), \
      TEST_MEM_SEG_REG(gs, reg, NOFS_MEM_PTR),          \
      TEST_MEM_SEG_REG(ss, reg, NOFS_MEM_PTR)

#define TEST_REG(reg) \
  TEST_SEG_REG(call, call, cs, reg, CS_JMP, false), TEST_REG_NOCALL(reg)

// Test case for "ret_cs".
#define TEST_RET() \
  { .name = "ret_cs", .fn = ret_cs, .type = CS_RET, .expect = false }

// All test cases.
Test testcases[] = {TEST_REG(rax),        TEST_REG(rbx), TEST_REG(rcx),
                    TEST_REG(rdx),        TEST_REG(rdi), TEST_REG(rsi),
                    TEST_REG_NOCALL(rsp), TEST_REG(rbp), TEST_RET()};

// Child processes may change FS, which will crash inside libc functions.
// Die immediately to avoid false failures caused by this.
void safe_exit() {
  asm("mov $0x3c, %rax\n"
      "xor %rdi, %rdi\n"
      "syscall");
}

// Run a single test case and print the result (plus the expected result, if
// requested).
void test_one(Test *test, bool show_expectations) {
  int status;
  bool test_result = false;
  void *arg = nullptr;
  int pid = fork();
  if (pid == -1) {
    std::perror("fork");
    exit(EXIT_FAILURE);
  }
  if (pid == 0) {
    // For "mov" and "movaps" tests that use fs: segment prefix, set FS to 0, so
    // that the test can address the allocated memory.
    // Note: libc relies on FS being non-zero for TLS, so we cannot call libc
    // functions from now on.
    if (test->type == FS_MEM_PTR) arch_prctl(ARCH_SET_FS, 0);
    switch (test->type) {
      case CS_JMP:
        arg = tagged_jump;
        break;
      case CS_RET:
        arg = tagged_jump;
        break;
      case FS_OFFSET:
        arg = tagged_offset;
        break;
      case FS_MEM_PTR:
      case NOFS_MEM_PTR:
        arg = tagged_addr;
        break;
    }
    test->fn(arg);
    safe_exit();
  } else {
    do {
      int w = waitpid(pid, &status, 0);
      if (w == -1) {
        std::perror("waitpid");
        exit(EXIT_FAILURE);
      }
      if (WIFEXITED(status)) {
        test_result = true;
      } else if (WIFSIGNALED(status)) {
        test_result = false;
      } else {
        std::perror("Unexpected wait status");
        exit(EXIT_FAILURE);
      }
      const char *result = test_result ? "PASS" : "FAIL";
      const char *expect =
          show_expectations
              ? (test_result == test->expect ? " (expected)" : " (unexpected)")
              : "";
      std::cout << test->name << ": " << result << expect << "\n";
    } while (!WIFEXITED(status) && !WIFSIGNALED(status));
  }
}

// Flip bits 57 and 58 to model a pointer tag.
// Also works with negative pointers for TLS accesses.
void *tagged_pointer(void *untagged) {
  uint64_t p = (uint64_t)untagged;
  p ^= (3UL << 57);
  return (void *)p;
}

// Set up globals that will be used by the test cases:
//  - tagged_addr - an address for "mov" and "movaps" tests;
//  - tagged_offset - a negative offset for "tls" tests;
//  - tagged_jump - a piece of code terminating the process.
void prepare_targets(bool use_tagging) {
  tagged_addr = mmap(nullptr, 0x1000, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  tagged_offset = (void *)(-64L);
  tagged_jump = mmap(nullptr, 0x1000, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  // Inline the implementation of safe_exit():
  //   mov $0x3c, %rax
  //   nop
  //   xor %rdi, %rdi;
  //   syscall
  ((uint64_t *)tagged_jump)[0] = 0x900000003cc0c748;
  ((uint64_t *)tagged_jump)[1] = 0x050fff3148;
  mprotect(tagged_jump, 0x1000, PROT_READ | PROT_EXEC);

  if (use_tagging) {
    tagged_addr = tagged_pointer(tagged_addr);
    tagged_offset = tagged_pointer(tagged_offset);
    tagged_jump = tagged_pointer(tagged_jump);
  }
}

// Parse the command line args and run the tests.
int main(int argc, char *argv[]) {
  bool use_tagging = true;
  bool show_expectations = false;

  std::set<std::string> args;
  for (int i = 1; i < argc; i++) {
    args.insert(argv[i]);
  }

  if (args.find("notag") != args.end()) {
    use_tagging = false;
    args.erase("notag");
  }

  if (args.find("expect") != args.end()) {
    show_expectations = true;
    args.erase("expect");
  }

  if (!try_enable_tagging(false))
    std::cerr << "Pointer tagging not supported, proceeding without it.\n";
  prepare_targets(use_tagging);
  for (Test t : testcases) {
    if (args.empty() || (args.find(t.name) != args.end()))
      test_one(&t, show_expectations);
  }
  return 0;
}
