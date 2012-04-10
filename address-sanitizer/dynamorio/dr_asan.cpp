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
  case OP_xadd:
    // TODO: support std::ios_base::Init::Init()
    // e.g. `std::cout << "Hello!\n";`
    // f0 41 0f c1 07          lock xadd %eax,(%r15)
    return false;
  }

  if (instr_ok_to_mangle(instr) == false)  // TODO: WTF is this?
    return false;

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
  // instructions that don't change flags.

  if (!TESTALL(EFLAGS_WRITE_6, flags) || TESTANY(EFLAGS_READ_6, flags)) {
    // TODO: for some reason, spilling eflags makes ASAN RTL
    // a bit crazy: it detects a simple OOB write as use-after-free...
#if 0
#if defined(VERBOSE_VERBOSE)
    dr_printf("Spilling eflags...\n");
#endif
    need_to_restore_eflags = true;
    dr_save_arith_flags(drcontext, bb, i, SPILL_SLOT_3);
#endif
  }

#if 0
  dr_printf("==DRASAN== DEBUG: %d %d %d %d\n",
            opnd_is_memory_reference(op),
            opnd_is_base_disp(op),
            opnd_get_index(op),
            opnd_is_far_memory_reference(op)
            );
#endif

  reg_id_t R1 = opnd_get_base(op),  // Register #2 memory address is already there!
           R1_8 = reg_32_to_opsz(R1, OPSZ_1),  // TODO: on x64?
           R2 = (R1 == DR_REG_XCX ? DR_REG_XDX : DR_REG_XCX),
           R2_8 = reg_32_to_opsz(R2, OPSZ_1);

  // TODO: support std::ios_base::Init::Init()
  // e.g. `std::cout << "Hello!\n";`
  if (R1 == DR_REG_INVALID) {
    // 80 3d 18 0b 20 00 00 cmp    <rel> 0x00007f0d996c0010 $0x00
    return;
  }

  CHECK(reg_to_pointer_sized(R1) == R1);  // otherwise R2 may be wrong.

  // Save the current values of R1 and R2.
  dr_save_reg(drcontext, bb, i, R1, SPILL_SLOT_1);
  // TODO: Something smarter than spilling a "fixed" register R2?
  dr_save_reg(drcontext, bb, i, R2, SPILL_SLOT_2);

  PRE(i, shr(drcontext, opnd_create_reg(R1), OPND_CREATE_INT8(3)));
#if __WORDSIZE == 32
  PRE(i, mov_ld(drcontext, opnd_create_reg(R2),
                OPND_CREATE_MEM32(R1,0x20000000)));
  PRE(i, test(drcontext, opnd_create_reg(R2_8), opnd_create_reg(R2_8)));
#else
  PRE(i, mov_imm(drcontext, opnd_create_reg(R2),
                OPND_CREATE_INTPTR(1ull << 44)));
  PRE(i, or(drcontext, opnd_create_reg(R2), opnd_create_reg(R1)));
  PRE(i, cmp(drcontext, OPND_CREATE_MEMPTR(R2,0), OPND_CREATE_INT8(0)));
#endif

  instr_t *OK_label = INSTR_CREATE_label(drcontext);
  PRE(i, jcc(drcontext, OP_je_short, opnd_create_instr(OK_label)));

  opnd_size_t access_size = opnd_get_size(op);
  CHECK(access_size != OPSZ_NA);
  if (access_size != OPSZ_8) {
    // Slowpath to support accesses smaller than pointer-sized.
    dr_restore_reg(drcontext, bb, i, R1, SPILL_SLOT_1);
    PRE(i, and(drcontext, opnd_create_reg(R1), OPND_CREATE_INT8(7)));
    switch (access_size) {
      case OPSZ_4:
        PRE(i, add(drcontext, opnd_create_reg(R1), OPND_CREATE_INT8(3)));
        break;
      case OPSZ_2:
        PRE(i, add(drcontext, opnd_create_reg(R1), OPND_CREATE_INT8(2)));
        break;
      case OPSZ_1:
        PRE(i, inc(drcontext, opnd_create_reg(R1)));
        break;
      default:
        CHECK(0);
    }
    PRE(i, cmp(drcontext, opnd_create_reg(R1_8), opnd_create_reg(R2_8)));
    PRE(i, jcc(drcontext, OP_je_short, opnd_create_instr(OK_label)));
  }

  // Trap code:
  // 1) Restore the original access address in XAX 
  dr_restore_reg(drcontext, bb, i, R1, SPILL_SLOT_1);
  // 2) Pass the original address as an argument...
  PRE(i, push(drcontext, opnd_create_reg(R1)));
  // 3) Call the right __asan_report_{load,store}{1,2,4,8}
  int sz_idx = -1;
  switch (access_size) {
    case OPSZ_1:  sz_idx = 0; break;
    case OPSZ_2:  sz_idx = 1; break;
    case OPSZ_4:  sz_idx = 2; break;
    case OPSZ_8:  sz_idx = 3; break;
    case OPSZ_16: sz_idx = 4; break;
  }
  AsanCallbacks::Report on_error = g_callbacks.report[is_write][sz_idx];
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
    dr_restore_arith_flags(drcontext, bb, i, SPILL_SLOT_3);
  }

  // The original instruction is left untouched. The above instrumentation is just
  // a prefix.
}

static dr_emit_flags_t
event_basic_block(void *drcontext, void *tag, instrlist_t *bb,
                  bool for_trace, bool translating)
{
  // TOFILE: `tag` should be (byte*)? or app_pc?

  // TODO: only start instrumentation after asan_init finishes or force a call
  // to asan_init() on the first bb and discard translations afterwards?

  module_data_t *md = dr_lookup_module((byte*)tag);
  if (md == NULL) {
    // TODO: WTF?
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
            tag, mod_name.c_str(), translating ? "true" : "false");
  instrlist_disassemble(drcontext, (byte*)tag, bb, STDOUT);
#elif defined(VERBOSE)
  if (translating == false)
    dr_printf("Instrumenting BB at %p [from %s]\n", tag, mi->path->c_str());
#endif

  for (instr_t *i = instrlist_first(bb); i != NULL; i = instr_get_next(i)) {
    if (!WantToInstrument(i))
      continue;

#if defined(VERBOSE_VERBOSE)
    uint flags = instr_get_arith_flags(i);
    dr_printf("+%d -> to be instrumented! [flags = 0x%08X]\n",
              instr_get_app_pc(i) - (byte*)tag, flags);
#endif

    if (instr_reads_memory(i)) {
      // Instrument memory reads
      bool instrumented_anything = false;
      for (int s = 0; s < instr_num_srcs(i); s++) {
        opnd_t op = instr_get_src(i, s);
        if (!OperandIsInteresting(op) || opnd_get_base(op) == DR_REG_NULL)
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
        if (!OperandIsInteresting(op) || opnd_get_base(op) == DR_REG_NULL)
          continue;

        CHECK(!instrumented_anything);
        instrumented_anything = true;
        InstrumentMops(drcontext, bb, i, op, true);
      }
    }
  }

#if defined(VERBOSE_VERBOSE)
  dr_printf("\nFinished instrumenting dynamorio_basic_block(tag="PFX")\n", tag);
  instrlist_disassemble(drcontext, (byte*)tag, bb, STDOUT);
#endif
  return DR_EMIT_DEFAULT;
}

void module_loaded(void *drcontext, const module_data_t *info, bool loaded) {
#if defined(VERBOSE)
  dr_printf("==DRASAN== Loaded module: %s [%p...%p]\n",
            info->full_path, info->start, info->end);
#endif

  static int loaded_modules = 0;
  if (loaded_modules++ == 0) {
    // TODO: First module - always the app?
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
        if (DRSYM_SUCCESS != drsym_lookup_symbol(info->full_path,
                                                 name_buffer,
                                                 &offset, 0)) {
          dr_printf("Couldn't find `%s` in %s\n", name_buffer, info->full_path);
          continue;
        }
        #ifdef VERBOSE_VERBOSE
          dr_printf("Found %s @ %p\n", name_buffer, info->start + offset);
        #endif
        g_callbacks.report[is_write][size_l2] =
            (AsanCallbacks::Report)(info->start + offset);
      }
    }
  }
}

void module_unloaded(void *drcontext, const module_data_t *info) {
  dr_printf("==DRASAN== Unloaded module: %s [%p...%p]\n",
            info->full_path, info->start, info->end);
  // TODO: cleanup
  CHECK(!"Not implemented");
}

void event_exit() {
  dr_printf("==DRASAN== DONE\n");
  drsym_exit();
}

DR_EXPORT void dr_init(client_id_t id) {
  drsym_init(NULL);
  dr_register_exit_event(event_exit);
  dr_register_bb_event(event_basic_block);
  dr_register_module_load_event(module_loaded);
  dr_register_module_unload_event(module_unloaded);
  dr_printf("==DRASAN== Starting!\n");
}
