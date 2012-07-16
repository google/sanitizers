/* Copyright 2011 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// This file is a part of AddressSanitizer, an address sanity checker.

// Implementation of DynamoRIO instrumentation for ASan

#include "dr_api.h"
#include "drutil.h"

#include <algorithm>
#include <string>
#include <set>
#include <vector>

using std::string;

#define TESTALL(mask, var) (((mask) & (var)) == (mask))
#define TESTANY(mask, var) (((mask) & (var)) != 0)

#define CHECK_IMPL(condition, file, line) \
    do { \
      if (!(condition)) { \
        dr_fprintf(STDERR, "Check failed: `%s`\nat %s:%d\n", #condition, \
                   file, line); \
        dr_abort(); \
      } \
    } while(0)  // TODO: stacktrace

#define CHECK(condition) CHECK_IMPL(condition, __FILE__, __LINE__)

//#define VERBOSE
//#define VERBOSE_VERBOSE

#if defined(VERBOSE_VERBOSE) && !defined(VERBOSE)
# define VERBOSE
#endif

#ifndef BINARY_INSTRUMENTED
# define BINARY_INSTRUMENTED 1
#endif

namespace {

struct AsanCallbacks {
  typedef void (*Report)(void*);
  Report report[2 /* load/store */][5 /* 1,2,4,8,16 */];
  void (*__asan_init)(void);
};

class ModuleData {
 public:
  ModuleData();
  ModuleData(const module_data_t *info);
  // Yes, we want default copy, assign, and dtor semantics.

 public:
  app_pc start_;
  app_pc end_;
  // Full path to the module.
  string path_;
  bool should_instrument_;
  bool executed_;
};

// TODO: on Windows, we may have multiple RTLs in one process.
AsanCallbacks g_callbacks = {0};

string g_app_path;

// A vector of loaded modules sorted by module bounds.  We lookup the current PC
// in here from the bb event.  This is better than an rb tree because the lookup
// is faster and the bb event occurs far more than the module load event.
std::vector<ModuleData> g_module_list;

ModuleData::ModuleData()
  : start_(NULL),
    end_(NULL),
    path_(""),
    should_instrument_(false),
    executed_(false)
{}

ModuleData::ModuleData(const module_data_t *info)
  : start_(info->start),
    end_(info->end),
    path_(info->full_path),
    // We'll check the black/white lists later and adjust this.
    should_instrument_(true),
    executed_(false)
{}

void InitializeAsanCallbacks() {
  static bool initialized = false;
  CHECK(!initialized);
  initialized = true;

  module_data_t *app = dr_lookup_module_by_name(dr_get_application_name());
  if (!app) {
    dr_printf("%s - oops, dr_lookup_module_by_name failed!\n", dr_get_application_name());
    CHECK(app);
  }
  g_app_path = app->full_path;

  for (int is_write = 0; is_write < 2; ++is_write) {
    for (int size_l2 = 0; size_l2 < 5; ++size_l2) {
      int size = 1 << size_l2;

      char name_buffer[128];
      dr_snprintf(name_buffer, sizeof(name_buffer),
                  "__asan_report_%s%d",
                  is_write ? "store" : "load", size);
      #ifdef VERBOSE_VERBOSE
      dr_printf("Searching %s...\r", name_buffer);
      #endif
      void (*report_func)() = dr_get_proc_address(app->handle, name_buffer);
      if (report_func == NULL) {
        dr_printf("Couldn't find `%s` in %s\n", name_buffer, app->full_path);
        continue;
      }
      #ifdef VERBOSE_VERBOSE
      dr_printf("Found %s @ %p\n", name_buffer, report_func);
      #endif
      g_callbacks.report[is_write][size_l2] =
          (AsanCallbacks::Report)(report_func);
    }
  }

  // DR uses LD_PRELOAD to take over, and currently __asan_init is run before DR
  // initializes.  This is good because it sets up the shadow memory for us, but
  // could change in the future if DR gets early injection.  Just to be safe, we
  // call __asan_init, which is a nop if it's already initialized.  We also use
  // this pointer to detect modules that use asan instrumentation.
  g_callbacks.__asan_init = dr_get_proc_address(app->handle, "__asan_init");
  g_callbacks.__asan_init();

  dr_free_module_data(app);
}

// Currently, we are only interested in base+index+displacement memory operands
// that don't use XSP or XBP as the base.  These are most likely to be involved
// in buggy pointer arithmetic in the application.
// timurrrr: wait a sec, what about accessing local variables on the stack via
// XBP+offset? On one hand, we don't insert redzones around them in the
// hybrid-instrumented code; on the other we still want to report OOBs/UARs on
// stack-var-passed-to-the-other-threads.
//
// TODO: Handle absolute addresses and PC-relative addresses.  These are
// unlikely to have bugs because they are most likely generated by the compiler
// to access globals or the GOT, but we have seen cases involving ODR and two
// globals with different types at the same address in ASan.
// TODO: Handle TLS accesses via FS or GS.  DR assumes all other segments have a
// zero base anyway.
bool OperandIsInteresting(opnd_t opnd) {
  // TOTHINK: we may access waaaay beyound the stack, do we need to check it?
  return (opnd_is_base_disp(opnd) &&
          opnd_get_segment(opnd) == DR_REG_NULL &&
          !opnd_uses_reg(opnd, DR_REG_XSP) &&
          !opnd_uses_reg(opnd, DR_REG_XBP));
}

bool WantToInstrument(instr_t *instr) {
  switch (instr_get_opcode(instr)) {
  // TODO: support the instructions excluded below:
  case OP_rep_cmps:
    // f3 a6    rep cmps %ds:(%rsi) %es:(%rdi) %rsi %rdi %rcx -> %rsi %rdi %rcx
    return false;

  case OP_prefetcht0:  // WTF?
    return false;
  }

  CHECK(instr_ok_to_mangle(instr) == true);

  if (instr_reads_memory(instr)) {
    for (int s = 0; s < instr_num_srcs(instr); s++) {
      opnd_t op = instr_get_src(instr, s);
      if (OperandIsInteresting(op))
        return true;
    }
  }

  if (instr_writes_memory(instr)) {
    for (int d = 0; d < instr_num_dsts(instr); d++) {
      opnd_t op = instr_get_dst(instr, d);
      if (OperandIsInteresting(op))
        return true;
    }
  }

  return false;
}

#define PRE(at, what) instrlist_meta_preinsert(bb, at, INSTR_CREATE_##what);
#define PREF(at, what) instrlist_meta_preinsert(bb, at, what);

void InstrumentMops(void *drcontext, instrlist_t *bb,
                           instr_t *i, opnd_t op, bool is_write)
{
  bool need_to_restore_eflags = false;
  uint flags = instr_get_arith_flags(i);
  // TODO: do something smarter with flags and spills in general?
  // For example, spill them only once for a sequence of instrumented
  // instructions that don't change/read flags.

  if (!TESTALL(EFLAGS_WRITE_6, flags) || TESTANY(EFLAGS_READ_6, flags)) {
#if defined(VERBOSE_VERBOSE)
    dr_printf("Spilling eflags...\n");
#endif
    need_to_restore_eflags = true;
    // TODO: Maybe sometimes don't need to 'seto'.
    // TODO: Maybe sometimes don't want to spill XAX here?
    // TODO: No need to spill XAX here if XAX is not used in the BB.
    dr_save_reg(drcontext, bb, i, DR_REG_XAX, SPILL_SLOT_1);
    dr_save_arith_flags_to_xax(drcontext, bb, i);
    dr_save_reg(drcontext, bb, i, DR_REG_XAX, SPILL_SLOT_3);
    dr_restore_reg(drcontext, bb, i, DR_REG_XAX, SPILL_SLOT_1);
  }

#if 0
  dr_printf("==DRASAN== DEBUG: %d %d %d %d %d %d\n",
            opnd_is_memory_reference(op),
            opnd_is_base_disp(op),
            opnd_get_index(op),
            opnd_is_far_memory_reference(op),
            opnd_is_reg_pointer_sized(op),
            opnd_is_base_disp(op) ? opnd_get_disp(op) : -1
            );
#endif

  reg_id_t R1;
  bool address_in_R1 = false;
  if (opnd_is_base_disp(op) && opnd_get_index(op) == DR_REG_NULL &&
      opnd_get_disp(op) == 0) {
    // If this is a simple access with no offset or index, we can just use the
    // base for R1.
    address_in_R1 = true;
    R1 = opnd_get_base(op);
  } else {
    // Otherwise, we need to compute the addr into R1.
    // TODO: reuse some spare register? e.g. r15 on x64
    // TODO: might be used as a non-mem-ref register?
    R1 = DR_REG_XAX;
  }
  if (!reg_is_pointer_sized(R1)) {
    // This happened for OP_prefetcht0.
    instr_disassemble(drcontext, i, STDERR);
    dr_fprintf(STDERR, "\n");
  }
  CHECK(reg_is_pointer_sized(R1));  // otherwise R1_8 and R2 may be wrong.
  reg_id_t R1_8 = reg_32_to_opsz(IF_X64_ELSE(reg_64_to_32(R1), R1), OPSZ_1);

  // Pick R2 that's not R1 or used by the operand.  It's OK if the instr uses
  // R2 elsewhere, since we'll restore it before instr.
  reg_id_t GPR_TO_USE_FOR_R2[] = {
    DR_REG_XAX, DR_REG_XBX, DR_REG_XCX, DR_REG_XDX
    // Don't forget to update the +4 below if you add anything else!
  };
  std::set<reg_id_t> unused_registers(GPR_TO_USE_FOR_R2, GPR_TO_USE_FOR_R2+4);
  unused_registers.erase(R1);
  for (int j = 0; j < opnd_num_regs_used(op); j++) {
    unused_registers.erase(opnd_get_reg_used(op, j));
  }

  CHECK(unused_registers.size() > 0);
  reg_id_t R2 = *unused_registers.begin(),
           R2_8 = reg_resize_to_opsz(R2, OPSZ_1);
  CHECK(R1 != R2);

  // Save the current values of R1 and R2.
  dr_save_reg(drcontext, bb, i, R1, SPILL_SLOT_1);
  // TODO: Something smarter than spilling a "fixed" register R2?
  dr_save_reg(drcontext, bb, i, R2, SPILL_SLOT_2);

  if (!address_in_R1)
    CHECK(drutil_insert_get_mem_addr(drcontext, bb, i, op, R1, R2));
  PRE(i, shr(drcontext, opnd_create_reg(R1), OPND_CREATE_INT8(3)));
  PRE(i, mov_imm(drcontext, opnd_create_reg(R2),
                 OPND_CREATE_INTPTR(IF_X64_ELSE(1ull << 44, 1 << 29))));
  PRE(i, or(drcontext, opnd_create_reg(R2), opnd_create_reg(R1)));
  PRE(i, cmp(drcontext, OPND_CREATE_MEM8(R2,0), OPND_CREATE_INT8(0)));

  // TODO: Idea: look at lea + jecxz instruction to avoid flags usage.  Might be
  // too complicated to always get ecx if it's the base reg, though.  Also,
  // jecxz is an old instruction, we need to double check it's performance on
  // new microarchitectures.
  // TODO: move the slow path to the end of the BB to improve the ICache usage.
  instr_t *OK_label = INSTR_CREATE_label(drcontext);
  PRE(i, jcc(drcontext, OP_je_short, opnd_create_instr(OK_label)));

  opnd_size_t op_size = opnd_get_size(op);
  CHECK(op_size != OPSZ_NA);
  uint access_size = opnd_size_in_bytes(op_size);
  if (access_size > 8) {
    // TODO: handle larger accesses
    access_size = 8;
  }

  if (access_size < 8) {
    // TODO: the second memory load in not necessary, see the prev load.
    PRE(i, mov_ld(drcontext, opnd_create_reg(R1), OPND_CREATE_MEMPTR(R2,0)));
    PRE(i, mov_ld(drcontext, opnd_create_reg(R2_8), opnd_create_reg(R1_8)));
    // Slowpath to support accesses smaller than pointer-sized.
    // TODO: do we need to restore R1 if address_in_R1 == false?
    dr_restore_reg(drcontext, bb, i, R1, SPILL_SLOT_1);
    if (!address_in_R1) {
      // Assuming R2 is not clobbered here, which is true unless op has a
      // segment.
      CHECK(opnd_get_segment(op) == DR_REG_NULL);
      CHECK(drutil_insert_get_mem_addr(drcontext, bb, i, op, R1, R2));
    }
    PRE(i, and(drcontext, opnd_create_reg(R1), OPND_CREATE_INT8(7)));
    if (access_size > 1) {
      PRE(i, add(drcontext, opnd_create_reg(R1),
                 OPND_CREATE_INT8(access_size - 1)));
    }
    PRE(i, cmp(drcontext, opnd_create_reg(R1_8), opnd_create_reg(R2_8)));
    PRE(i, jcc(drcontext, OP_jl_short, opnd_create_instr(OK_label)));
  }

  // Trap code:
  // 1) Restore the original access address in R1.
  // Restore both R1 and R2 as the original address may depend on either of
  // them. Probably it's not necessary to always restore both, but this is
  // only executed once in a app lifetime, so don't bother much yet.
  dr_restore_reg(drcontext, bb, i, R1, SPILL_SLOT_1);
  if (!address_in_R1) {
    dr_restore_reg(drcontext, bb, i, R2, SPILL_SLOT_2);
    CHECK(drutil_insert_get_mem_addr(drcontext, bb, i, op, R1, R2));
  }
  // 2) Pass the original address as an argument...
#if __WORDSIZE == 32
  PRE(i, push(drcontext, opnd_create_reg(R1)));
#else
  // timurrrr: You've meant IF_WINDOWS_ELSE(DR_REG_RCX, DR_REG_RDI)?
  reg_id_t regparm_0 = IF_X64_ELSE(DR_REG_RDI, DR_REG_RCX);
  if (R1 != regparm_0)
    PRE(i, mov_ld(drcontext, opnd_create_reg(regparm_0), opnd_create_reg(R1)));
#endif
  // 3) Call the right __asan_report_{load,store}{1,2,4,8}
  int sz_idx = 0;
  // Log2-analog below.
  // TODO: in rare weird cases like OPSZ_6 we'll be reporting wrong access
  // sizes (e.g. 4-byte instead of 6-byte).
  {
    uint as = access_size;
    while (as > 1) {
      sz_idx++;
      as /= 2;
    }
  }
  CHECK(sz_idx < 5);
  AsanCallbacks::Report *on_error = &g_callbacks.report[is_write][sz_idx];
  // TODO: this trashes the stack, likely debugger-unfriendly.
  // TODO: enforce on_error != NULL when we link the RTL in the binary.
  // TODO: Align the stack.
#if __WORDSIZE == 32
  // Push the app PC as the return address:
  //   push instr_get_app_pc(i)
  //   jmp __asan_report_XXX
  PRE(i, push(drcontext, OPND_CREATE_INT32(instr_get_app_pc(i))));
  PRE(i, jmp(drcontext, opnd_create_pc((byte*)*on_error)));
#else
  // 64-bit has two problems: reachability, and no 64-bit immediate push.  So,
  // we split the push into a push+mov_st, and jump through the client's memory,
  // which DR guarantees to be reachable from the code cache.
  //   push (uint32_t)app_pc
  //   mov  (uint32_t)(app_pc >> 32) %(rsp,4)
  //   jmp  g_callbacks_report_XXX(%rip)
  app_pc pc = instr_get_app_pc(i);
  int lo = (int)(ptr_int_t)pc;
  int hi = (int)((ptr_int_t)pc >> 32);
  PRE(i, push_imm(drcontext, OPND_CREATE_INT32(lo)));
  PRE(i, mov_st(drcontext, OPND_CREATE_MEM32(DR_REG_XSP, 4),
                OPND_CREATE_INT32(hi)));
  PRE(i, jmp_ind(drcontext, opnd_create_rel_addr((byte*)on_error, OPSZ_PTR)));
#endif
  // TODO: we end up with no symbols in the ASan report stacks because we do
  // post-process symbolization and the DRASan frames have PCs not present in
  // the binary.
  // We may want to get back to ud2a handling in the RTL as we did before as we
  // can set translation field to the original instruction in DR and make stacks
  // look very sane.
  //

  PREF(i, OK_label);
  // Restore the registers and flags.
  dr_restore_reg(drcontext, bb, i, R1, SPILL_SLOT_1);
  dr_restore_reg(drcontext, bb, i, R2, SPILL_SLOT_2);

  if (need_to_restore_eflags) {
#if defined(VERBOSE_VERBOSE)
    dr_printf("Restoring eflags\n");
#endif
    // TODO: Check if it's reverse to the dr_restore_reg above and optimize.
    dr_save_reg(drcontext, bb, i, DR_REG_XAX, SPILL_SLOT_1);
    dr_restore_reg(drcontext, bb, i, DR_REG_XAX, SPILL_SLOT_3);
    dr_restore_arith_flags_from_xax(drcontext, bb, i);
    dr_restore_reg(drcontext, bb, i, DR_REG_XAX, SPILL_SLOT_1);
  }

  // The original instruction is left untouched. The above instrumentation is just
  // a prefix.
}

// For use with binary search.  Modules shouldn't overlap, so we shouldn't have
// to look at end_.  If that can happen, we won't support such an application.
bool ModuleDataCompareStart(const ModuleData &left,
                                   const ModuleData &right) {
  return left.start_ < right.start_;
}

// Look up the module containing PC.  Should be relatively fast, as its called
// for each bb instrumentation.
ModuleData *LookupModuleByPC(app_pc pc) {
  ModuleData fake_mod_data;
  fake_mod_data.start_ = pc;
  std::vector<ModuleData>::iterator it =
      lower_bound(g_module_list.begin(), g_module_list.end(), fake_mod_data,
                  ModuleDataCompareStart);
  if (it == g_module_list.end() || pc < it->start_)
    --it;
  CHECK(it->start_ <= pc);
  if (pc >= it->end_) {
    // We're past the end of this module.  We shouldn't be in the next module,
    // or lower_bound lied to us.
    ++it;
    CHECK(it == g_module_list.end() || pc < it->start_);
    return NULL;
  }

  // OK, we found the module.
  return &*it;
}

bool ShouldInstrumentNonModuleCode() {
  // TODO(rnk): Turning this on hits CHECK(t->chunk_state == CHUNK_AVAILABLE) in
  // asan_allocator.cc.  Perhaps there's a bug in our instru that we hit in
  // JITed code, or like the libc issue, the ASan RTL calls some non-module code
  // and instrumenting it is bad.
  //
  // Another thing that doesn't work: gettimeofday goes to vdso area and causes
  // our instru to fault.  We can probably exclude just vdso and instrument
  // normal JITed code.
  return false;  // TODO(rnk): Should be a flag.
}

bool ShouldInstrumentModule(ModuleData *mod_data) {
  // TODO(rnk): Flags for blacklist would get wired in here.
  const string &path = mod_data->path_;
  if (path == g_app_path) {
    return false;
  }
  if (path.find("/libc-") != string::npos ||
      path.find("/ld-") != string::npos ||
      path.find("libosmesa") != string::npos ||
      // ASan i#80: Don't instrument compiler instrumented code.
      // TODO: We can check if the module imports __asan_init, but we'll need DR
      // support or a bunch of ELF parsing routines in dr_asan.
      path.find("libppGoogleNaClPluginChrome") != string::npos ||
      path.find("/libpthread") != string::npos) {
    // TODO(rnk): Instrument libc.  The ASan RTL calls libc on addresses that we
    // can't map to the shadow space.
    return false;
  }
  return true;
}

dr_emit_flags_t event_basic_block(void *drcontext, void *tag, instrlist_t *bb,
                                  bool for_trace, bool translating) {
  app_pc pc = dr_fragment_app_pc(tag);
  ModuleData *mod_data = LookupModuleByPC(pc);
  if (mod_data == NULL && !ShouldInstrumentNonModuleCode())
    return DR_EMIT_DEFAULT;
  CHECK(mod_data->should_instrument_);
  string mod_path = (mod_data ? mod_data->path_ : "<no module, JITed?>");
#if defined(VERBOSE)
# if defined(VERBOSE_VERBOSE)
  dr_printf("============================================================\n");
# endif
  if (mod_data && !mod_data->executed_) {
    mod_data->executed_ = true;  // Nevermind this race.
    dr_printf("Executing from new module: %s\n", mod_path.c_str());
  }
  dr_printf("BB to be instrumented: %p [from %s]; translating = %s\n",
            pc, mod_path.c_str(), translating ? "true" : "false");
  if (mod_data) {
    // Match standard asan trace format for free symbols.
    // #0 0x7f6e35cf2e45  (/blah/foo.so+0x11fe45)
    dr_printf(" #0 %p (%s+%p)\n", pc,
              mod_data->path_.c_str(),
              pc - mod_data->start_);
  }
# if defined(VERBOSE_VERBOSE)
  instrlist_disassemble(drcontext, pc, bb, STDOUT);
# endif
#endif

  for (instr_t *i = instrlist_first(bb); i != NULL; i = instr_get_next(i)) {
    if (!WantToInstrument(i))
      continue;

#if defined(VERBOSE_VERBOSE)
    app_pc orig_pc = dr_fragment_app_pc(tag);
    uint flags = instr_get_arith_flags(i);
    dr_printf("+%d -> to be instrumented! [opcode=%d, flags = 0x%08X]\n",
              instr_get_app_pc(i) - orig_pc, instr_get_opcode(i), flags);
#endif

    // TODO: drutil_expand_rep_string/_ex, otherwise we're only checking
    // the first mop. However, we probably only want the first and the last one?

    // TODO: Some instructions (e.g. lock xadd) may read & write the same memory
    // location. Optimize the instrumentation to only check the write.

    if (instr_reads_memory(i)
        // Don't instrument reads in libX for now.  XChangeProperty has a small
        // buffer overread.
        && mod_path.find("libX") == string::npos
        ) {
      // Instrument memory reads
      bool instrumented_anything = false;
      for (int s = 0; s < instr_num_srcs(i); s++) {
        opnd_t op = instr_get_src(i, s);
        if (!OperandIsInteresting(op))
          continue;

        // TODO: CMPS may not pass this check.
        // Probably, should use drutil_expand_rep_string
        CHECK(!instrumented_anything);
        instrumented_anything = true;
        InstrumentMops(drcontext, bb, i, op, false);
      }
    }

    if (instr_writes_memory(i)) {
      // Instrument memory writes
      bool instrumented_anything = false;
      for (int d = 0; d < instr_num_dsts(i); d++) {
        opnd_t op = instr_get_dst(i, d);
        if (!OperandIsInteresting(op))
          continue;

        CHECK(!instrumented_anything);
        instrumented_anything = true;
        InstrumentMops(drcontext, bb, i, op, true);
      }
    }
  }

  // TODO: optimize away redundant restore-spill pairs?

#if defined(VERBOSE_VERBOSE)
  dr_printf("\nFinished instrumenting dynamorio_basic_block(PC="PFX")\n", pc);
  instrlist_disassemble(drcontext, pc, bb, STDOUT);
#endif
  return DR_EMIT_DEFAULT;
}

void event_module_load(void *drcontext, const module_data_t *info, bool loaded) {
  // Insert the module into the list while maintaining the ordering.
  ModuleData mod_data(info);
  std::vector<ModuleData>::iterator it =
      upper_bound(g_module_list.begin(), g_module_list.end(), mod_data,
                  ModuleDataCompareStart);
  it = g_module_list.insert(it, mod_data);
  // Check if we should instrument this module.
  it->should_instrument_ = ShouldInstrumentModule(&*it);
  if (!it->should_instrument_) {
    dr_module_set_should_instrument(info->handle, false);
  }

#if defined(VERBOSE)
  dr_printf("==DRASAN== Loaded module: %s [%p...%p], instrumentation is %s\n",
            info->full_path, info->start, info->end,
            it->should_instrument_ ? "on" : "off");
#endif
}

void event_module_unload(void *drcontext, const module_data_t *info) {
#if defined(VERBOSE)
  dr_printf("==DRASAN== Unloaded module: %s [%p...%p]\n",
            info->full_path, info->start, info->end);
#endif

  // Remove the module from the list.
  ModuleData mod_data(info);
  std::vector<ModuleData>::iterator it =
      lower_bound(g_module_list.begin(), g_module_list.end(), mod_data,
                  ModuleDataCompareStart);
  // It's a bug if we didn't actually find the module.
  CHECK(it != g_module_list.end() &&
        it->start_ == mod_data.start_ &&
        it->end_ == mod_data.end_ &&
        it->path_ == mod_data.path_);
  g_module_list.erase(it);
}

void event_exit() {
#if defined(VERBOSE)
  dr_printf("==DRASAN== DONE\n");
#endif
}

}  // namespace

DR_EXPORT void dr_init(client_id_t id) {
  string app_name = dr_get_application_name();
  // This blacklist will still run these apps through DR's code cache.  On the
  // other hand, we are able to follow children of these apps.
  // TODO(rnk): Once DR has detach, we could just detach here.  Alternatively,
  // if DR had a fork or exec hook to let us decide there, that would be nice.
  // TODO: make the blacklist cmd-adjustable.
  if (app_name == "python" ||
      app_name == "bash" || app_name == "sh" ||
      app_name == "true" || app_name == "exit" ||
      app_name == "yes" || app_name == "echo")
    return;

  InitializeAsanCallbacks();

  // Standard DR events.
  dr_register_exit_event(event_exit);
  dr_register_bb_event(event_basic_block);
  dr_register_module_load_event(event_module_load);
  dr_register_module_unload_event(event_module_unload);
#if defined(VERBOSE)
  dr_printf("==DRASAN== Starting!\n");
#endif
}
