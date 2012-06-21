/* GCC instrumentation plugin for ThreadSanitizer.
 * Copyright (c) 2012, Google Inc. All rights reserved.
 * Author: Dmitry Vyukov (dvyukov)
 *
 * IT is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3, or (at your option) any later
 * version. See http://www.gnu.org/licenses/
 */

#include "config.h"
#include "system.h"
#include "coretypes.h"
#include "tree.h"
#include "intl.h"
#include "tm.h"
#include "basic-block.h"
#include "gimple.h"
#include "function.h"
#include "tree-flow.h"
#include "tree-pass.h"
#include "tree-iterator.h"
#include "cfghooks.h"
#include "langhooks.h"
#include "output.h"
#include "options.h"
#include "target.h"
#include "cgraph.h"
#include "diagnostic.h"

/* Number of instrumented memory accesses in the current function.  */

static int func_mops;

/* Number of function calls in the current function.  */

static int func_calls;

/* Returns a definition of a runtime functione with type TYP and name NAME.  */

static tree
build_func_decl (tree typ, const char *name)
{
  tree decl;

  decl = build_fn_decl (name, typ);
  TREE_NOTHROW (decl) = 1;
  DECL_ATTRIBUTES (decl) = tree_cons (get_identifier ("leaf"),
                                     NULL, DECL_ATTRIBUTES (decl));
  DECL_ASSEMBLER_NAME (decl);
  return decl;
}

/* Builds the following decl
   void __tsan_read/writeX (void *addr);  */

static tree
get_memory_access_decl (int is_write, unsigned size)
{
  tree typ, *decl;
  char fname [64];
  static tree cache [2][17];

  is_write = !!is_write;
  if (size <= 1)
    size = 1;
  else if (size <= 3)
    size = 2;
  else if (size <= 7)
    size = 4;
  else if (size <= 15)
    size = 8;
  else
    size = 16;
  decl = &cache[is_write][size];
  if (*decl == NULL)
    {
      snprintf(fname, sizeof fname, "__tsan_%s%d",
               is_write ? "write" : "read", size);
      typ = build_function_type_list (void_type_node, ptr_type_node, NULL_TREE);
      *decl = build_func_decl (typ, fname);
    }
  return *decl;
}

/* Builds the following decl
   void __tsan_vptr_update (void *vptr, void *val);  */

static tree
get_vptr_update_decl (void)
{
  tree typ;
  static tree decl;

  if (decl != NULL)
    return decl;
  typ = build_function_type_list (void_type_node,
                                  ptr_type_node, ptr_type_node, NULL_TREE);
  decl = build_func_decl (typ, "__tsan_vptr_update");
  return decl;
}


/* Builds the following decl
   void __tsan_init (void);  */

static tree
get_init_decl (void)
{
  tree typ;
  static tree decl;

  if (decl != NULL)
    return decl;
  typ = build_function_type_list (void_type_node, NULL_TREE);
  decl = build_func_decl (typ, "__tsan_init");
  return decl;
}

/* Builds the following decl
   void __tsan_func_entry (void *addr);  */

static tree
get_func_entry_decl (void)
{
  tree typ;
  static tree decl;

  if (decl != NULL)
    return decl;
  typ = build_function_type_list (void_type_node, ptr_type_node, NULL_TREE);
  decl = build_func_decl (typ, "__tsan_func_entry");
  return decl;
}

/* Builds the following decl
   void __tsan_func_exit (void);  */

static tree
get_func_exit_decl (void)
{
  tree typ;
  static tree decl;

  if (decl != NULL)
    return decl;
  typ = build_function_type_list (void_type_node, NULL_TREE);
  decl = build_func_decl (typ, "__tsan_func_exit");
  return decl;
}

/* Builds the following gimple sequence:
   __tsan_read/writeX (&EXPR);  */

static gimple_seq
instr_memory_access (tree expr, int is_write)
{
  tree addr_expr, expr_type, call_expr, fdecl;
  gimple_seq gs;
  unsigned size;

  gcc_assert (is_gimple_addressable (expr));
  addr_expr = build_addr (unshare_expr (expr), current_function_decl);
  expr_type = TREE_TYPE (expr);
  while (TREE_CODE (expr_type) == ARRAY_TYPE)
    expr_type = TREE_TYPE (expr_type);
  size = (TREE_INT_CST_LOW (TYPE_SIZE (expr_type))) / BITS_PER_UNIT;
  fdecl = get_memory_access_decl (is_write, size);
  call_expr = build_call_expr (fdecl, 1, addr_expr);
  gs = NULL;
  force_gimple_operand (call_expr, &gs, true, 0);
  return gs;
}

/* Builds the following gimple sequence:
   __tsan_vptr_update (&EXPR, RHS);  */

static gimple_seq
instr_vptr_update (tree expr, tree rhs)
{
  tree expr_ptr, call_expr, fdecl;
  gimple_seq gs;

  expr_ptr = build_addr (unshare_expr (expr), current_function_decl);
  fdecl = get_vptr_update_decl ();
  call_expr = build_call_expr (fdecl, 2, expr_ptr, rhs);
  gs = NULL;
  force_gimple_operand (call_expr, &gs, true, 0);
  return gs;
}

/* Returns gimple seq that needs to be inserted at function entry.  */

static gimple_seq
instr_func_entry (void)
{
  tree retaddr_decl, pc_addr, fdecl, call_expr;
  gimple_seq gs;

  retaddr_decl = implicit_built_in_decls [BUILT_IN_RETURN_ADDRESS];
  pc_addr = build_call_expr (retaddr_decl, 1, integer_zero_node);
  fdecl = get_func_entry_decl ();
  call_expr = build_call_expr (fdecl, 1, pc_addr);
  gs = NULL;
  force_gimple_operand (call_expr, &gs, true, 0);
  return gs;
}

/* Returns gimple seq that needs to be inserted before function exit.  */

static gimple_seq
instr_func_exit (void)
{
  tree fdecl, call_expr;
  gimple_seq gs;

  fdecl = get_func_exit_decl ();
  call_expr = build_call_expr (fdecl, 0);
  gs = NULL;
  force_gimple_operand (call_expr, &gs, true, 0);
  return gs;
}

/* Sets location LOC for all gimples in the SEQ.  */

static void
set_location (gimple_seq seq, location_t loc)
{
  gimple_seq_node n;

  for (n = gimple_seq_first (seq); n != NULL; n = n->next)
    gimple_set_location (n->stmt, loc);
}

/* Check as to whether EXPR refers to a store to vptr.  */

static tree
is_vptr_store (gimple stmt, tree expr, int is_write)
{
  if (is_write == 1
      && gimple_assign_single_p (stmt)
      && TREE_CODE (expr) == COMPONENT_REF)
    {
      tree field = TREE_OPERAND (expr, 1);
      if (TREE_CODE (field) == FIELD_DECL
          && DECL_VIRTUAL_P (field))
        return gimple_assign_rhs1 (stmt);
    }
  return NULL;
}

/* Checks as to whether EXPR refers to constant var/field/param.
   Don't bother to instrument them.  */

static int
is_load_of_const (tree expr, int is_write)
{
  if (is_write)
    return 0;
  if (TREE_CODE (expr) == COMPONENT_REF)
    expr = TREE_OPERAND (expr, 1);
  if (TREE_CODE (expr) == VAR_DECL
      || TREE_CODE (expr) == PARM_DECL
      || TREE_CODE (expr) == FIELD_DECL)
    {
      if (TREE_READONLY (expr))
        return 1;
    }
  return 0;
}

/* Instruments EXPR if needed.  */

static void
instrument_expr (gimple_stmt_iterator gsi, tree expr, int is_write)
{
  enum tree_code tcode;
  unsigned fld_off, fld_size;
  tree base, rhs;
  gimple stmt;
  gimple_seq gs;
  location_t loc;

  base = get_base_address (expr);
  if (base == NULL_TREE
      || TREE_CODE (base) == SSA_NAME
      || TREE_CODE (base) == STRING_CST)
    return;

  tcode = TREE_CODE (expr);

  /* Below are things we do not instrument
     (no possibility of races or not implemented yet).  */
  if (/* Compiler-emitted artificial variables.  */
      (DECL_P (expr) && DECL_ARTIFICIAL (expr))
      /* The var does not live in memory -> no possibility of races.  */
      || (tcode == VAR_DECL
          && TREE_ADDRESSABLE (expr) == 0
          && DECL_EXTERNAL (expr) == 0)
      /* Not implemented.  */
      || TREE_CODE (TREE_TYPE (expr)) == RECORD_TYPE
      /* Not implemented.  */
      || tcode == CONSTRUCTOR
      /* Not implemented.  */
      || tcode == PARM_DECL
      /* Load of a const variable/parameter/field.  */
      || is_load_of_const (expr, is_write))
    return;

  if (tcode == COMPONENT_REF)
    {
      tree field = TREE_OPERAND (expr, 1);
      if (TREE_CODE (field) == FIELD_DECL)
        {
          fld_off = TREE_INT_CST_LOW (DECL_FIELD_BIT_OFFSET (field));
          fld_size = TREE_INT_CST_LOW (DECL_SIZE (field));
          if (((fld_off % BITS_PER_UNIT) != 0)
              || ((fld_size % BITS_PER_UNIT) != 0))
            {
              /* As of now it crashes compilation.
                 TODO: handle bit-fields as if touching the whole field.  */
              return;
            }
        }
    }

  /* TODO: handle other cases
     (FIELD_DECL, MEM_REF, ARRAY_RANGE_REF, TARGET_MEM_REF, ADDR_EXPR).  */
  if (tcode != ARRAY_REF
      && tcode != VAR_DECL
      && tcode != COMPONENT_REF
      && tcode != INDIRECT_REF
      && tcode != MEM_REF)
    return;

  stmt = gsi_stmt (gsi);
  loc = gimple_location (stmt);
  rhs = is_vptr_store (stmt, expr, is_write);
  if (rhs == NULL)
    gs = instr_memory_access (expr, is_write);
  else
    gs = instr_vptr_update (expr, rhs);
  set_location (gs, loc);
  /* Instrumentation for assignment of a function result
     must be inserted after the call.  Instrumentation for
     reads of function arguments must be inserted before the call.
     That's because the call can contain synchronization.  */
  if (is_gimple_call (stmt) && is_write)
    gsi_insert_seq_after (&gsi, gs, GSI_NEW_STMT);
  else
    gsi_insert_seq_before (&gsi, gs, GSI_SAME_STMT);
}

/* Instruments the gimple pointed to by GSI.  */

static void
instrument_gimple (gimple_stmt_iterator gsi)
{
  unsigned i;
  gimple stmt;
  enum gimple_code gcode;
  tree rhs;
  tree lhs;

  stmt = gsi_stmt (gsi);
  gcode = gimple_code (stmt);
  if (gcode == GIMPLE_CALL)
    {
      func_calls += 1;
    }
  else if (gcode == GIMPLE_ASSIGN)
    {
      /* Handle assignment lhs as store.  */
      lhs = gimple_assign_lhs (stmt);
      instrument_expr (gsi, lhs, 1);
      /* Handle operands as loads.  */
      for (i = 1; i < gimple_num_ops (stmt); i++)
        {
          rhs = gimple_op (stmt, i);
          instrument_expr (gsi, rhs, 0);
        }
    }
}

/* Instruments all interesting memory accesses in the current function.  */

static void
instrument_memory_accesses (void)
{
  basic_block bb;
  gimple_stmt_iterator gsi;

  FOR_EACH_BB (bb)
    {
      for (gsi = gsi_start_bb (bb); !gsi_end_p (gsi); gsi_next (&gsi))
        {
          instrument_gimple (gsi);
        }
    }
}

/* Instruments function entry.  */

static void
instrument_func_entry (void)
{
  gimple_seq seq;
  basic_block entry_bb;
  edge entry_edge;
  gimple_stmt_iterator gsi;

  /* Insert new BB before the first BB.  */
  seq = instr_func_entry ();
  gcc_assert (seq != NULL);
  entry_bb = ENTRY_BLOCK_PTR;
  entry_edge = single_succ_edge (entry_bb);
  set_location (seq, cfun->function_start_locus);
  entry_bb = split_edge (entry_edge);
  gsi = gsi_start_bb (entry_bb);
  gsi_insert_seq_after (&gsi, seq, GSI_NEW_STMT);
}

/* Instruments function exits.  */

static void
instrument_func_exit (void)
{
  location_t loc;
  gimple_seq seq;
  basic_block exit_bb;
  gimple_stmt_iterator gsi;
  gimple stmt;
  edge e;
  edge_iterator ei;

  /* Find all function exits.  */
  exit_bb = EXIT_BLOCK_PTR;
  FOR_EACH_EDGE (e, ei, exit_bb->preds)
    {
      gsi = gsi_last_bb (e->src);
      stmt = gsi_stmt (gsi);
      gcc_assert (gimple_code (stmt) == GIMPLE_RETURN);
      loc = gimple_location (stmt);
      seq = instr_func_exit ();
      gcc_assert (seq != NULL);
      set_location (seq, loc);
      gsi_insert_seq_before (&gsi, seq, GSI_SAME_STMT);
    }
}

/* ThreadSanitizer instrumentation pass.  */

static unsigned
tsan_pass (void)
{
  struct gimplify_ctx gctx;

  func_calls = 0;
  func_mops = 0;
  push_gimplify_context (&gctx);
  instrument_memory_accesses ();
  if (func_calls || func_mops)
    {
      instrument_func_entry ();
      instrument_func_exit ();
    }
  pop_gimplify_context (NULL);
  return 0;
}

/* The pass's gate.  */

static bool
tsan_gate (void)
{
  return flag_tsan != 0;
}

/* Inserts __tsan_init () into the list of CTORs.  */

void tsan_finish_file (void)
{
  tree ctor_statements;

  ctor_statements = NULL_TREE;
  append_to_statement_list (build_call_expr (get_init_decl (), 0),
                            &ctor_statements);
  cgraph_build_static_cdtor ('I', ctor_statements,
                             MAX_RESERVED_INIT_PRIORITY - 1);
}

/* The pass descriptor.  */

struct gimple_opt_pass pass_tsan = {{
  GIMPLE_PASS,
  "tsan",                               /* name  */
  tsan_gate,                            /* gate  */
  tsan_pass,                            /* execute  */
  NULL,                                 /* sub  */
  NULL,                                 /* next  */
  0,                                    /* static_pass_number  */
  TV_NONE,                              /* tv_id  */
  PROP_ssa | PROP_cfg,                  /* properties_required  */
  0,                                    /* properties_provided  */
  0,                                    /* properties_destroyed  */
  0,                                    /* todo_flags_start  */
  TODO_dump_cgraph | TODO_dump_func | TODO_verify_all
    | TODO_update_ssa | TODO_update_address_taken /* todo_flags_finish  */
}};
