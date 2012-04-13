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
#include "dr/ext/drutil/drutil.h"
#include "dr/ext/drsyms/drsyms.h"

#include <string>
#include <vector>
using namespace std;

#define TESTALL(mask, var) (((mask) & (var)) == (mask))
#define TESTANY(mask, var) (((mask) & (var)) != 0)

#define CHECK_IMPL(condition, file, line) \
    do { \
      if (!(condition)) { \
        dr_printf("Check failed: `%s`\nat %s:%d\n", #condition, file, line); \
        dr_abort(); \
      } \
    } while(0)  // TODO: stacktrace

#define CHECK(condition) CHECK_IMPL(condition, __FILE__, __LINE__)

//#define VERBOSE_VERBOSE

#if defined(VERBOSE_VERBOSE) && !defined(VERBOSE)
# define VERBOSE
#endif

struct AsanCallbacks {
  typedef void (*Report)(void*);
  Report report[2 /* load/store */][5 /* 1,2,4,8,16 */];
};

// TODO: on Windows, we may have multiple RTLs in one process.
AsanCallbacks g_callbacks = {0};

void InitializeAsanCallbacks() {
  static bool initialized = false;

  if (initialized)
    return;
  initialized = true;

  module_data_t *app = dr_lookup_module_by_name(dr_get_application_name());
  if (!app) {
    dr_printf("%s - oops, dr_lookup_module_by_name failed!\n", dr_get_application_name());
    CHECK(app);
  }

  for (int is_write = 0; is_write < 2; ++is_write) {
    for (int size_l2 = 0; size_l2 < 5; ++size_l2) {
      int size = 1 << size_l2;
      size_t offset = -1;

      char name_buffer[128];
      dr_snprintf(name_buffer, sizeof(name_buffer),
                  "__asan_report_%s%d",
                  is_write ? "store" : "load", size);
      #ifdef VERBOSE_VERBOSE
      dr_printf("Searching %s...\r", name_buffer);
      #endif
      // TODO: Use dr_get_proc_address() instead?
      if (DRSYM_SUCCESS != drsym_lookup_symbol(app->full_path,
                                               name_buffer,
                                               &offset, 0)) {
        dr_printf("Couldn't find `%s` in %s\n", name_buffer, app->full_path);
        continue;
      }
      #ifdef VERBOSE_VERBOSE
      dr_printf("Found %s @ %p\n", name_buffer, app->start + offset);
      #endif
      g_callbacks.report[is_write][size_l2] =
          (AsanCallbacks::Report)(app->start + offset);
    }
  }

  dr_free_module_data(app);
}

bool OperandIsInteresting(opnd_t opnd) {
  // TOTHINK: we may access waaaay beyound the stack, do we need to check it?
  return
      (opnd_is_memory_reference(opnd) &&
       (!opnd_is_base_disp(opnd) ||
        (reg_to_pointer_sized(opnd_get_base(opnd)) != DR_REG_XSP &&
         reg_to_pointer_sized(opnd_get_base(opnd)) != DR_REG_XBP) ||
        opnd_get_index(opnd) != DR_REG_NULL ||
        opnd_is_far_memory_reference(opnd)));
}

bool WantToInstrument(instr_t *instr) {
  switch (instr_get_opcode(instr)) {
  // TODO: support the instructions excluded below:
  case OP_rep_cmps:
    // f3 a6    rep cmps %ds:(%rsi) %es:(%rdi) %rsi %rdi %rcx -> %rsi %rdi %rcx
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

static void InstrumentMops(void *drcontext, instrlist_t *bb,
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
    dr_save_arith_flags(drcontext, bb, i, SPILL_SLOT_1);
    dr_save_reg(drcontext, bb, i, DR_REG_XAX, SPILL_SLOT_3);
    dr_restore_reg(drcontext, bb, i, DR_REG_XAX, SPILL_SLOT_1);
    // TODO: sometimes don't want to spill XAX here?
  }

#if 0
  dr_printf("==DRASAN== DEBUG: %d %d %d %d %d %d\n",
            opnd_is_memory_reference(op),
            opnd_is_base_disp(op),
            opnd_get_index(op),
            opnd_is_far_memory_reference(op),
            opnd_is_reg_pointer_sized(op),
            opnd_get_disp(op)
            );
#endif

  reg_id_t R1;
  bool address_in_R1 = false;
  if (opnd_is_base_disp(op) && opnd_get_disp(op) == 0 &&
      !opnd_is_abs_addr(op) && !opnd_is_rel_addr(op)) {
    // TODO: is this the correct condition above?
    address_in_R1 = true;
    R1 = opnd_get_base(op);
  } else {
    // TODO: reuse some spare register? e.g. r15 on x64
    R1 = DR_REG_XAX;
  }
  CHECK(reg_is_pointer_sized(R1));  // otherwise R1_8 and R2 may be wrong.
  reg_id_t R1_8 = reg_32_to_opsz(IF_X64_ELSE(reg_64_to_32(R1), R1), OPSZ_1);

  // TODO: R2 could also be the index reg for op, pick one that isn't.
  reg_id_t R2 = (R1 == DR_REG_XCX ? DR_REG_XDX : DR_REG_XCX),
           R2_8 = reg_32_to_opsz(IF_X64_ELSE(reg_64_to_32(R2), R2), OPSZ_1);

  // Save the current values of R1 and R2.
  dr_save_reg(drcontext, bb, i, R1, SPILL_SLOT_1);
  // TODO: Something smarter than spilling a "fixed" register R2?
  dr_save_reg(drcontext, bb, i, R2, SPILL_SLOT_2);

  if (!address_in_R1)
    CHECK(drutil_insert_get_mem_addr(drcontext, bb, i, op, R1, R2));
  PRE(i, shr(drcontext, opnd_create_reg(R1), OPND_CREATE_INT8(3)));
#if __WORDSIZE == 32
  PRE(i, mov_ld(drcontext, opnd_create_reg(R2),
                OPND_CREATE_MEM32(R1,0x20000000)));
  PRE(i, test(drcontext, opnd_create_reg(R2_8), opnd_create_reg(R2_8)));
#else
  PRE(i, mov_imm(drcontext, opnd_create_reg(R2),
                OPND_CREATE_INTPTR(1ull << 44)));
  PRE(i, or(drcontext, opnd_create_reg(R2), opnd_create_reg(R1)));
  PRE(i, cmp(drcontext, OPND_CREATE_MEM8(R2,0), OPND_CREATE_INT8(0)));
#endif

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
    PRE(i, mov_ld(drcontext, opnd_create_reg(R1), OPND_CREATE_MEMPTR(R2,0)));
    PRE(i, mov_ld(drcontext, opnd_create_reg(R2_8), opnd_create_reg(R1_8)));
    // Slowpath to support accesses smaller than pointer-sized.
    // TODO: do we need to restore R1 if address_in_R1 == false?
    dr_restore_reg(drcontext, bb, i, R1, SPILL_SLOT_1);
    if (!address_in_R1) {
      // TODO: assuming R2 is not scratched here.
      CHECK(drutil_insert_get_mem_addr(drcontext, bb, i, op, R1, R2));
    }
    PRE(i, and(drcontext, opnd_create_reg(R1), OPND_CREATE_INT8(7)));
    if (access_size > 1) {
      PRE(i, add(drcontext, opnd_create_reg(R1),
                 OPND_CREATE_INT8(access_size - 1)));
    }
    PRE(i, cmp(drcontext, opnd_create_reg(R1_8), opnd_create_reg(R2_8)));
    PRE(i, jcc(drcontext, OP_jb_short, opnd_create_instr(OK_label)));
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
  // TODO: Check the Windows calling convention.
#if __WORDSIZE == 32
  PRE(i, push(drcontext, opnd_create_reg(R1)));
#else
  if (R1 != DR_REG_RDI)
    PRE(i, mov_ld(drcontext, opnd_create_reg(DR_REG_RDI), opnd_create_reg(R1)));
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
  AsanCallbacks::Report on_error = g_callbacks.report[is_write][sz_idx];
  // TODO: this trashes the stack, likely debugger-unfriendly.
  // TODO: enforce on_error != NULL when we link the RTL in the binary.
  PRE(i, call(drcontext, opnd_create_pc((byte*)on_error)));
  // TODO: we end up with no symbols in the ASan report stacks because we do
  // post-process symbolization and the DRASan frames have PCs not present in
  // the binary.
  // We may want to get back to ud2a handling in the RTL as we did before as we
  // can set translation field to the original instruction in DR and make stacks
  // look very sane.

  PREF(i, OK_label);
  // Restore the registers and flags.
  dr_restore_reg(drcontext, bb, i, R1, SPILL_SLOT_1);
  dr_restore_reg(drcontext, bb, i, R2, SPILL_SLOT_2);

  if (need_to_restore_eflags) {
#if defined(VERBOSE_VERBOSE)
    dr_printf("Restoring eflags\n");
#endif
    dr_save_reg(drcontext, bb, i, DR_REG_XAX, SPILL_SLOT_1);
    dr_restore_reg(drcontext, bb, i, DR_REG_XAX, SPILL_SLOT_3);
    dr_restore_arith_flags(drcontext, bb, i, SPILL_SLOT_1);
  }

  // The original instruction is left untouched. The above instrumentation is just
  // a prefix.
}

static dr_emit_flags_t
event_basic_block(void *drcontext, void *tag, instrlist_t *bb,
                  bool for_trace, bool translating)
{
  // TODO: only start instrumentation after asan_init finishes or force a call
  // to asan_init() on the first bb and discard translations afterwards?
  app_pc orig_pc = dr_fragment_app_pc(tag);
  module_data_t *md = dr_lookup_module(orig_pc);
  if (md == NULL) {
    // We're in the JIT code.
    // TODO: test & handle
    return DR_EMIT_DEFAULT;
  }
  string mod_name(md->full_path);
  dr_free_module_data(md);

  if (mod_name.find("/libc") != string::npos)
    return DR_EMIT_DEFAULT;
  if (mod_name.find("pintest_so.so") == string::npos &&
      mod_name.find("/usr/lib/") != 0 &&
      mod_name.find("/lib/") != 0)
    return DR_EMIT_DEFAULT;

  // TODO: these fail probably because asan_init was not called yet.
  if (mod_name.find("/lib/ld") == 0)
    return DR_EMIT_DEFAULT;
  if (mod_name.find("/lib/libpthread") == 0)
    return DR_EMIT_DEFAULT;

  // TODO: blacklist RTL functions.

#if defined(VERBOSE_VERBOSE)
  dr_printf("============================================================\n");
  dr_printf("BB to be instrumented: %p [from %s]; translating = %s\n",
            orig_pc, mod_name.c_str(), translating ? "true" : "false");
  instrlist_disassemble(drcontext, (byte*)tag, bb, STDOUT);
#elif defined(VERBOSE)
  if (translating == false)
    dr_printf("Instrumenting BB at %p [from %s]\n", orig_pc, mi->path->c_str());
#endif

  for (instr_t *i = instrlist_first(bb); i != NULL; i = instr_get_next(i)) {
    if (!WantToInstrument(i))
      continue;

#if defined(VERBOSE_VERBOSE)
    uint flags = instr_get_arith_flags(i);
    dr_printf("+%d -> to be instrumented! [opcode=%d, flags = 0x%08X]\n",
              instr_get_app_pc(i) - orig_pc, instr_get_opcode(i), flags);
#endif

    // TODO: drutil_expand_rep_string/_ex, otherwise we're only checking
    // the first mop. However, we probably only want the first and the last one?

    // TODO: Some instructions (e.g. lock xadd) may read & write the same memory
    // location. Optimize the instrumentation to only check the write.

    if (instr_reads_memory(i)) {
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
  dr_printf("\nFinished instrumenting dynamorio_basic_block(PC="PFX")\n", tag);
  instrlist_disassemble(drcontext, orig_pc, bb, STDOUT);
#endif
  return DR_EMIT_DEFAULT;
}

void module_loaded(void *drcontext, const module_data_t *info, bool loaded) {
#if defined(VERBOSE)
  dr_printf("==DRASAN== Loaded module: %s [%p...%p]\n",
            info->full_path, info->start, info->end);
#endif
  InitializeAsanCallbacks();
}

void event_exit() {
#if defined(VERBOSE)
  dr_printf("==DRASAN== DONE\n");
#endif
  drsym_exit();
}

DR_EXPORT void dr_init(client_id_t id) {
  string app_name = dr_get_application_name();
  // TODO: make the blacklist cmd-adjustable.
  if (app_name == "python" ||
      app_name == "bash" || app_name == "sh" ||
      app_name == "true" || app_name == "exit" ||
      app_name == "yes" || app_name == "echo")
    return;

  drsym_init(NULL);
  dr_register_exit_event(event_exit);
  dr_register_bb_event(event_basic_block);
  dr_register_module_load_event(module_loaded);
#if defined(VERBOSE)
  dr_printf("==DRASAN== Starting!\n");
#endif
}
