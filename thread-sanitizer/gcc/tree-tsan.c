/* ThreadSanitizer, a data race detector.
   Copyright (C) 2011 Free Software Foundation, Inc.
   Contributed by Dmitry Vyukov <dvyukov@google.com>

This file is part of GCC.

GCC is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 3, or (at your option)
any later version.

GCC is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with GCC; see the file COPYING3.  If not see
<http://www.gnu.org/licenses/>.  */

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

//#include <stdlib.h>
//#include <stdio.h>

/* ThreadSanitizer is a data race detector for C/C++ programs.
   http://code.google.com/p/data-race-test/wiki/ThreadSanitizer

   The tool consists of two parts:
   instrumentation module (this file) and a run-time library.
   The instrumentation module maintains shadow call stacks
   and intercepts interesting memory accesses.
   The instrumentation is enabled with -ftsan flag.

   Instrumentation for shadow stack maintenance is as follows:
   void somefunc ()
   {
     __tsan_shadow_stack [-1] = __builtin_return_address (0);
     __tsan_shadow_stack++;
     // function body
     __tsan_shadow_stack--;
   }

   Interception for memory access interception is as follows:
   *addr = 1;
   __tsan_handle_mop (addr, flags);
   where flags are (is_sblock | (is_store << 1) | ((sizeof (*addr) - 1) << 2).
   is_sblock is used merely for optimization purposes and can always
   be set to 1, see comments in instrument_mops function.

   Ignore files can be used to selectively non instrument some functions.
   Ignore file is specified with -ftsan-ignore=filename flag.
   There are 3 types of ignores: (1) do not instrument memory accesses
   in the function, (2) do not create sblocks in the function
   and (3) recursively ignore memory accesses in the function.
   That last ignore type requires additional instrumentation of the form:
   void somefunc ()
   {
     __tsan_thread_ignore++;
     // function body
     __tsan_thread_ignore--;
   }

   The run-time library provides __tsan_handle_mop function,
   definitions of __tsan_shadow_stack and __tsan_thread_ignore variables,
   and intercepts synchronization related functions.  */

#define TSAN_IGNORE "__tsan_thread_ignore"
#define TSAN_STACK "__tsan_shadow_stack"
#define TSAN_MOP "__tsan_handle_mop"
#define TSAN_INIT "__tsan_init"
#define TSAN_PERFIX "__tsan_"
#define MAX_MOP_BYTES 16
#define SBLOCK_SIZE 5

enum tsan_ignore_type
{
  tsan_ignore_none  = 1 << 0, /* Do not ignore.  */
  tsan_ignore_func  = 1 << 1, /* Completely ignore the whole func.  */
  tsan_ignore_mop   = 1 << 2, /* Do not instrument accesses.  */
  tsan_ignore_rec   = 1 << 3, /* Do not instrument accesses recursively.  */
  tsan_ignore_hist  = 1 << 4  /* Do not create superblocks.  */
};

/* Info associated with each basic block.
   Used to determine super-blocks (see instrument_mops ()).  */

struct bb_data
{
  int         is_visited;
  int         has_sb;
  const char *sb_file;
  int         sb_line_min;
  int         sb_line_max;
};

/* Memory access descriptor.  */

struct mop_desc
{
  int                  is_call;
  int                  is_store;
  gimple_stmt_iterator gsi;
  tree                 expr;
};

/* Descriptor of an ignore file entry.  */

struct tsan_ignore_desc
{
  struct tsan_ignore_desc *next;
  enum tsan_ignore_type    type;
  char                    *name;
};

/* Number of instrumented memory accesses in the current function.  */

static int func_mops;

/* Number of function calls in the current function.  */

static int func_calls;

/* Ignore status for the current function (see tsan_ignore_type).  */

static enum tsan_ignore_type func_ignore;

static int ignore_init = 0;
static struct tsan_ignore_desc *ignore_head;

typedef struct mop_desc mop_desc;
DEF_VEC_O (mop_desc);
DEF_VEC_ALLOC_O (mop_desc, heap);
static VEC (mop_desc, heap) *mop_list;

/* Returns a definition of a runtime variable with type TYP and name NAME.  */

static tree
build_var_decl (tree typ, const char *name)
{
  tree id;
  tree decl;
  varpool_node_ptr var;

  /* Check if a user has defined it for testing.  */
  id = get_identifier (name);
  var = varpool_node_for_asm (id);
  if (var != NULL)
    {
      decl = var->decl;
      gcc_assert (TREE_CODE (decl) == VAR_DECL);
      return decl;
    }

  decl = build_decl (UNKNOWN_LOCATION, VAR_DECL, id, typ);
  TREE_STATIC (decl) = 1;
  TREE_PUBLIC (decl) = 1;
  DECL_EXTERNAL (decl) = 1;
  if (targetm.have_tls)
    DECL_TLS_MODEL (decl) = decl_default_tls_model (decl);
  TREE_USED (decl) = 1;
  TREE_THIS_VOLATILE (decl) = 1;
  SET_DECL_ASSEMBLER_NAME (decl, id);
  return decl;
}

/* Builds the following decl
   extern __thread void **__tsan_shadow_stack;  */

static tree
get_shadow_stack_decl (void)
{
  static tree decl;

  if (decl == NULL)
    decl = build_var_decl (build_pointer_type (ptr_type_node), TSAN_STACK);
  return decl;
}

/* Builds the following decl
   extern __thread int __tsan_thread_ignore;  */

static tree
get_thread_ignore_decl (void)
{
  static tree decl;

  if (decl == NULL)
    decl = build_var_decl (integer_type_node, TSAN_IGNORE);
  return decl;
}

/* Returns a definition of a runtime functione with type TYP and name NAME.  */

static tree
build_func_decl (tree typ, const char *name)
{
  tree id;
  cgraph_node_ptr func;
  tree decl;

  /* Check if a user has defined it for testing.  */
  id = get_identifier (name);
  func = cgraph_node_for_asm (id);
  if (func != NULL)
    {
      decl = func->decl;
      gcc_assert (TREE_CODE (decl) == FUNCTION_DECL);
      return decl;
    }

  decl = build_fn_decl (name, typ);
  TREE_NOTHROW (decl) = 1;
  DECL_ATTRIBUTES (decl) = tree_cons (get_identifier ("leaf"),
                                     NULL, DECL_ATTRIBUTES (decl));
  DECL_ASSEMBLER_NAME (decl);
  return decl;
}

/* Builds the following decl
   void __tsan_handle_mop (void *addr, unsigned flags);  */

static tree
get_handle_mop_decl (void)
{
  tree typ;
  static tree decl;

  if (decl != NULL)
    return decl;

  typ = build_function_type_list (void_type_node, ptr_type_node,
                                  integer_type_node , NULL_TREE);
  decl = build_func_decl (typ, TSAN_MOP);
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
  decl = build_func_decl (typ, TSAN_INIT);
  return decl;
}

/* Adds new ignore definition to the global list.
   TYPE is the ignore type (see tsan_ignore_type).
   NAME is the ignore pattern (e.g. "std*string*insert").  */

static void
ignore_append (enum tsan_ignore_type type, char *name)
{
  struct tsan_ignore_desc *desc;

  desc = XCNEW (struct tsan_ignore_desc);
  desc->type = type;
  desc->name = xstrdup (name);
  desc->next = ignore_head;
  ignore_head = desc;
}

/* Checks as to whether identifier STR matches template TEMPL.
   Templates can only contain '*', e.g. 'std*string*insert'.
   Templates implicitly start and end with '*'
   since they are matched against mangled names.
   Returns non-zero if STR is matched against TEMPL.  */

static int
ignore_match (char *templ, const char *str)
{
  char *tpos;
  const char *spos;

  while (templ && templ [0])
    {
      if (templ [0] == '*')
        {
          templ++;
          continue;
        }
      if (str [0] == 0)
        return 0;
      tpos = strchr (templ, '*');
      if (tpos != NULL)
        tpos [0] = 0;
      spos = strstr (str, templ);
      str = spos + strlen (templ);
      templ = tpos;
      if (tpos != NULL)
        tpos [0] = '*';
      if (spos == NULL)
        return 0;
    }
  return 1;
}

/* Loads ignore definitions from the file specified by -ftsan-ignore=filename.
   The result is stored in the global ignore_head list.
   Ignore files have the following format:

# This is a comment - ignored

# The below line says to not instrument memory accesses
# in all functions that match 'std*string*insert'
fun:std*string*insert

# The below line says to not instrument memory accesses
# in the function called 'foobar' *and* in all functions
# that it calls recursively
fun_r:foobar

# The below line says to not create superblocks
# in the function called 'barbaz'
fun_hist:barbaz

# Ignore all functions in the source file
src:atomic.c

# Everything else is uninteresting for us (e.g. obj:)
*/

static void
ignore_load (void)
{
  FILE *f;
  char *line;
  size_t linesz;
  ssize_t sz;
  char buf [PATH_MAX];

  if(getenv("GCCTSAN_PAUSE"))
    {
      int res;
      printf("ATTACH A DEBUGGER AND PRESS ENTER\n");
      res = scanf("%s", buf);
      (void)res;
    }

  if (flag_tsan_ignore == NULL || flag_tsan_ignore [0] == 0)
    return;

  f = fopen (flag_tsan_ignore, "r");
  if (f == NULL)
    {
      /* Try to open it relative to main_input_filename.  */
      strncpy (buf, main_input_filename, sizeof (buf));
      buf [sizeof (buf) - 1] = 0;
      line = strrchr (buf, '/');
      if (line != NULL)
        {
          line++;
          strncpy (line, flag_tsan_ignore, sizeof (buf) - (line - buf));
          buf [sizeof (buf) - 1] = 0;
          f = fopen (buf, "r");
        }
    }
  if (f == NULL)
    {
      error ("failed to open ignore file '%s'\n", flag_tsan_ignore);
      return;
    }

  line = 0;
  linesz = 0;
  while ((sz = getline (&line, &linesz, f)) != -1)
    {
      if (sz == 0)
        continue;
      /* Strip line terminator.  */
      if (line [sz - 1] == '\r' || line [sz - 1] == '\n')
        line [sz - 1] = 0;
      if (strncmp (line, "src:", sizeof ("src:") - 1) == 0)
        ignore_append (tsan_ignore_func, line + sizeof ("src:") - 1);
      else if (strncmp (line, "fun:", sizeof ("fun:") - 1) == 0)
        ignore_append (tsan_ignore_mop, line + sizeof ("fun:") - 1);
      else if (strncmp (line, "fun_r:", sizeof ("fun_r:") - 1) == 0)
        ignore_append (tsan_ignore_rec, line + sizeof ("fun_r:") - 1);
      else if (strncmp (line, "fun_hist:", sizeof ("fun_hist:") - 1) == 0)
        ignore_append (tsan_ignore_hist, line + sizeof ("fun_hist:") - 1);
      /* Other lines are not interesting.  */
    }

  free (line);
  fclose (f);
}

/* Returns ignore status for the current function.  */

static enum tsan_ignore_type
tsan_ignore (void)
{
  const char *func_name;
  const char *src_name;
  struct tsan_ignore_desc *desc;

  if (ignore_init == 0)
    {
      ignore_load ();
      ignore_init = 1;
    }

  /* Must be some artificial thunk function.  */
  if (DECL_ARTIFICIAL (cfun->decl) && DECL_IGNORED_P (cfun->decl))
    return tsan_ignore_func;

  src_name = expand_location (cfun->function_start_locus).file;
  if (src_name == NULL)
    src_name = "";

  func_name = IDENTIFIER_POINTER (DECL_ASSEMBLER_NAME (cfun->decl));
  /* Ignore all functions starting with __tsan_ - intended for testing.  */
  if (strncmp (func_name, TSAN_PERFIX, sizeof (TSAN_PERFIX) - 1) == 0)
    return tsan_ignore_func;

  /* Ignore global ctors.  */
  if (strncmp (func_name, "_GLOBAL", sizeof ("_GLOBAL") - 1) == 0)
    return tsan_ignore_func;

  for (desc = ignore_head; desc; desc = desc->next)
    {
      if (desc->type == tsan_ignore_func)
        {
          if (ignore_match (desc->name, src_name))
           return desc->type;
        }
      else if (ignore_match (desc->name, func_name))
       return desc->type;
    }
  return tsan_ignore_none;
}

/* Builds either (__tsan_shadow_stack += 1) or (__tsan_shadow_stack -= 1)
   expression depending on DO_DEC parameter.  Appends the result to SEQ.  */

static void
build_stack_op (gimple_seq *seq, bool do_dec)
{
  tree op_size;
  double_int op_size_cst;
  unsigned long long size_val;
  unsigned long long size_valhi;
  tree op_expr;
  gimple assign;
  tree sstack_decl;
  gimple_seq s;

  op_size = TYPE_SIZE (ptr_type_node);
  op_size_cst = tree_to_double_int (op_size);
  size_val = op_size_cst.low / BITS_PER_UNIT;
  size_valhi = 0;
  if (do_dec)
    {
      size_val = -size_val;
      size_valhi = -1;
    }
  op_size = build_int_cst_wide (sizetype, size_val, size_valhi);
  sstack_decl = get_shadow_stack_decl ();
  op_expr = build2 (POINTER_PLUS_EXPR, ptr_type_node, sstack_decl, op_size);

  s = NULL;
  op_expr = force_gimple_operand (op_expr, &s, true, NULL_TREE);
  gimple_seq_add_seq (seq, s);

  assign = gimple_build_assign (sstack_decl, op_expr);
  gimple_seq_add_stmt (seq, assign);
}

/* Builds either (__tsan_thread_ignore += 1) or (__tsan_thread_ignore -= 1)
   expression depending on OP parameter.  Stores the result in SEQ.  */

static void
build_rec_ignore_op (gimple_seq *seq, enum tree_code op)
{
  tree rec_expr;
  gimple_seq rec_inc;
  gimple rec_assign;
  tree ignore_decl;

  ignore_decl = get_thread_ignore_decl ();
  rec_expr = build2 (op, integer_type_node, ignore_decl, integer_one_node);
  rec_inc = NULL;
  rec_expr = force_gimple_operand (rec_expr, &rec_inc, true, NULL_TREE);
  gimple_seq_add_seq (seq, rec_inc);
  rec_assign = gimple_build_assign (ignore_decl, rec_expr);
  gimple_seq_add_stmt (seq, rec_assign);
}

/* Build the following gimple sequence:
   __tsan_shadow_stack [-1] = __builtin_return_address (0);
   Stores the result in SEQ.  */

static void
build_stack_assign (gimple_seq *seq)
{
  tree pc_addr;
  tree op_size;
  tree op_expr;
  tree stack_op;
  tree retaddr_decl;
  tree assign;

  retaddr_decl = implicit_built_in_decls [BUILT_IN_RETURN_ADDRESS];
  pc_addr = build_call_expr (retaddr_decl, 1, integer_zero_node);
  op_size = build_int_cst_wide (sizetype, -(POINTER_SIZE / BITS_PER_UNIT), -1);
  op_expr = build2 (POINTER_PLUS_EXPR, ptr_type_node,
                    get_shadow_stack_decl (), op_size);
  stack_op = build1 (INDIRECT_REF, ptr_type_node, op_expr);
  assign = build2 (MODIFY_EXPR, ptr_type_node, stack_op, pc_addr);
  force_gimple_operand (assign, seq, true, NULL_TREE);
}

/* Builds the following gimple sequence:
   __tsan_handle_mop (&EXPR,
                      (IS_SBLOCK | (IS_STORE << 1) | ((sizeof (EXPR) - 1) << 2);
   The result is stored in GSEQ.  */

static void
instr_mop (tree expr, int is_store, int is_sblock, gimple_seq *gseq)
{
  tree addr_expr;
  tree expr_type;
  unsigned size;
  unsigned flags;
  tree flags_expr;
  tree call_expr;

  gcc_assert (gseq != 0 && *gseq == 0);
  gcc_assert (is_gimple_addressable (expr));

  addr_expr = build_addr (unshare_expr (expr), current_function_decl);
  expr_type = TREE_TYPE (expr);
  while (TREE_CODE (expr_type) == ARRAY_TYPE)
    expr_type = TREE_TYPE (expr_type);
  size = TREE_INT_CST_LOW (TYPE_SIZE (expr_type));
  size = size / BITS_PER_UNIT;
  if (size > MAX_MOP_BYTES)
    size = MAX_MOP_BYTES;
  size -= 1;
  flags = ((!!is_sblock << 0) + (!!is_store << 1) + (size << 2));
  flags_expr = build_int_cst (unsigned_type_node, flags);
  call_expr = build_call_expr (get_handle_mop_decl (),
                               2, addr_expr, flags_expr);
  force_gimple_operand (call_expr, gseq, true, 0);
}

/* Builds the following gimple sequence:
   int is_store = (EXPR != RHS); // The temp is not actually introduced.
   __tsan_handle_mop (&EXPR,
                      (IS_SBLOCK | (IS_STORE << 1) | ((sizeof (EXPR) - 1) << 2);
   The result is stored in GSEQ.  */

static void
instr_vptr_store (tree expr, tree rhs, int is_sblock, gimple_seq *gseq)
{
  tree expr_ptr;
  tree addr_expr;
  tree expr_type;
  tree expr_size;
  double_int size;
  unsigned flags;
  tree flags_expr;
  gimple_seq flags_seq;
  gimple collect;
  tree is_store_expr;

  expr_ptr = build_addr (unshare_expr (expr), current_function_decl);
  addr_expr = force_gimple_operand (expr_ptr, gseq, true, NULL_TREE);
  expr_type = TREE_TYPE (expr);
  while (TREE_CODE (expr_type) == ARRAY_TYPE)
    expr_type = TREE_TYPE (expr_type);
  expr_size = TYPE_SIZE (expr_type);
  size = tree_to_double_int (expr_size);
  gcc_assert (size.high == 0 && size.low != 0);
  if (size.low > 128)
    size.low = 128;
  size.low = (size.low / 8) - 1;
  flags = ((!!is_sblock << 0) + (size.low << 2));
  flags_expr = build_int_cst (unsigned_type_node, flags);
  is_store_expr = build2 (NE_EXPR, unsigned_type_node,
                              build1 (VIEW_CONVERT_EXPR, size_type_node, expr),
                              build1 (VIEW_CONVERT_EXPR, size_type_node, rhs));
  is_store_expr = build2 (LSHIFT_EXPR, unsigned_type_node,
                              is_store_expr, integer_one_node);
  flags_expr = build2 (BIT_IOR_EXPR, unsigned_type_node,
                              is_store_expr, flags_expr);
  flags_seq = 0;
  flags_expr = force_gimple_operand (flags_expr, &flags_seq, true, NULL_TREE);
  gimple_seq_add_seq (gseq, flags_seq);
  collect = gimple_build_call (
      get_handle_mop_decl (), 2, addr_expr, flags_expr);
  gimple_seq_add_stmt (gseq, collect);
}

/* Returns true if function entry and exit need to be instrumented.  */

static bool
is_func_instrumentation_required (void)
{
  if (func_calls == 0 && func_mops == 0)
    return false;
  if (func_ignore != tsan_ignore_rec)
    return true;
  if (func_ignore == tsan_ignore_rec && func_calls != 0)
    return true;
  return false;
}

/* Returns gimple seq that needs to be inserted at function entry.  */

static gimple_seq
build_func_entry_instr (void)
{
  gimple_seq gs;

  gs = NULL;
  gcc_assert (is_func_instrumentation_required ());
  if (func_ignore != tsan_ignore_rec)
    {
      build_stack_assign (&gs);
      build_stack_op (&gs, false);
    }
  else
    build_rec_ignore_op (&gs, PLUS_EXPR);
  return gs;
}

/* Returns gimple seq that needs to be inserted before function exit.  */

static gimple_seq
build_func_exit_instr (void)
{
  gimple_seq gs;

  gs = NULL;
  gcc_assert (is_func_instrumentation_required ());
  if (func_ignore != tsan_ignore_rec)
    build_stack_op (&gs, true);
  else
    build_rec_ignore_op (&gs, MINUS_EXPR);
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
is_vptr_store (gimple stmt, tree expr, int is_store)
{
  if (is_store == 1
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
is_load_of_const (tree expr, int is_store)
{
  if (is_store)
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

/* Checks as to whether EXPR needs to be instrumented,
   if so puts it into the MOP_LIST.
   GSI is the iterator from which EXPR was extracted.
   IS_STORE says as to whether EXPR refers to a memory store
   or a memory load.  */

static void
handle_expr (gimple_stmt_iterator gsi, tree expr, int is_store,
             VEC (mop_desc, heap) **mop_list)
{
  enum tree_code tcode;
  struct mop_desc mop;
  unsigned fld_off;
  unsigned fld_size;
  tree base;


  base = get_base_address (expr);
  if (base == NULL_TREE
      || TREE_CODE (base) == SSA_NAME
      || TREE_CODE (base) == STRING_CST)
    return;

  tcode = TREE_CODE (expr);

  /* Below are things we do not instrument
     (no possibility of races or not implemented yet).  */
  if ((func_ignore & (tsan_ignore_mop | tsan_ignore_rec))
      /* Compiler-emitted artificial variables.  */
      || (DECL_P (expr) && DECL_ARTIFICIAL (expr))
      /* The var does not live in memory -> no possibility of races.  */
      || (tcode == VAR_DECL
          && TREE_ADDRESSABLE (expr) == 0
          && DECL_EXTERNAL (expr) == 0)
      /* TODO (dvyukov): not implemented.  */
      || TREE_CODE (TREE_TYPE (expr)) == RECORD_TYPE
      /* TODO (dvyukov): not implemented.  */
      || tcode == CONSTRUCTOR
      /* TODO (dvyukov): not implemented.  */
      || tcode == PARM_DECL
      /* Load of a const variable/parameter/field.  */
      || is_load_of_const (expr, is_store))
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
                 TODO (dvyukov): handle bit-fields as if touching
                 the whole field.  */
              return;
            }
        }
    }

  /* TODO (dvyukov): handle other cases
     (FIELD_DECL, MEM_REF, ARRAY_RANGE_REF, TARGET_MEM_REF, ADDR_EXPR).  */
  if (tcode != ARRAY_REF
      && tcode != VAR_DECL
      && tcode != COMPONENT_REF
      && tcode != INDIRECT_REF
      && tcode != MEM_REF)
    return;

  mop.is_call = 0;
  mop.gsi = gsi;
  mop.expr = expr;
  mop.is_store = is_store;
  VEC_safe_push (mop_desc, heap, *mop_list, &mop);
}

/* Collects all interesting memory accesses from the gimple pointed to by GSI
   into MOP_LIST.  */

static void
handle_gimple (gimple_stmt_iterator gsi, VEC (mop_desc, heap) **mop_list)
{
  unsigned i;
  struct mop_desc mop;
  gimple stmt;
  enum gimple_code gcode;
  tree rhs;
  tree lhs;

  stmt = gsi_stmt (gsi);
  gcode = gimple_code (stmt);
  if (gcode >= LAST_AND_UNUSED_GIMPLE_CODE)
    return;

  switch (gcode)
    {
      case GIMPLE_CALL:
        {
          func_calls += 1;
          memset (&mop, 0, sizeof (mop));
          mop.is_call = 1;
          VEC_safe_push (mop_desc, heap, *mop_list, &mop);
          break;
        }

      case GIMPLE_ASSIGN:
        {
          /* Handle assignment lhs as store.  */
          lhs = gimple_assign_lhs (stmt);
          handle_expr (gsi, lhs, 1, mop_list);

          /* Handle operands as loads.  */
          for (i = 1; i < gimple_num_ops (stmt); i++)
            {
              rhs = gimple_op (stmt, i);
              handle_expr (gsi, rhs, 0, mop_list);
            }
          break;
        }

      default:
        break;
    }
}

/* Instruments single basic block BB.
   BBD is the sblock info associated with the block.  */

static void
instrument_bblock (struct bb_data *bbd, basic_block bb)
{
  int ix;
  int is_sblock;
  gimple_stmt_iterator gsi;
  struct mop_desc *mop;
  gimple stmt;
  location_t loc;
  expanded_location eloc;
  gimple_seq instr_seq;
  tree rhs;

  /* Iterate over all gimples and collect interesting mops into mop_list.  */
  VEC_free (mop_desc, heap, mop_list);
  for (gsi = gsi_start_bb (bb); !gsi_end_p (gsi); gsi_next (&gsi))
    {
      handle_gimple (gsi, &mop_list);
    }

  mop = 0;
  for (ix = 0; VEC_iterate (mop_desc, mop_list, ix, mop); ix += 1)
    {
      if (mop->is_call != 0)
        {
          /* After a function call we must start a brand new sblock,
             because the function can contain synchronization.  */
          bbd->has_sb = 0;
          continue;
        }

      func_mops += 1;
      stmt = gsi_stmt (mop->gsi);
      loc = gimple_location (stmt);
      eloc = expand_location (loc);

      /* Check as to whether we may not set sblock flag for the access.  */
      is_sblock = (bbd->has_sb == 0
          || !(eloc.file != 0
              && bbd->sb_file != 0
              && strcmp (eloc.file, bbd->sb_file) == 0
              && eloc.line >= bbd->sb_line_min
              && eloc.line <= bbd->sb_line_max));

      if (func_ignore == tsan_ignore_hist)
        is_sblock = 0;

      if (is_sblock)
        {
          /* Start new sblock with new source info.  */
          bbd->has_sb = 1;
          bbd->sb_file = eloc.file;
          bbd->sb_line_min = eloc.line;
          bbd->sb_line_max = eloc.line + SBLOCK_SIZE;
        }

      instr_seq = 0;
      rhs = is_vptr_store (stmt, mop->expr, mop->is_store);
      if (rhs == NULL)
        instr_mop (mop->expr, mop->is_store, is_sblock, &instr_seq);
      else
        instr_vptr_store (mop->expr, rhs, is_sblock, &instr_seq);
      gcc_assert (instr_seq != 0);
      set_location (instr_seq, loc);
      /* Instrumentation for assignment of a function result
         must be inserted after the call.  Instrumentation for
         reads of function arguments must be inserted before the call.
         That's because the call can contain synchronization.  */
      if (is_gimple_call (stmt) && mop->is_store == 1)
        gsi_insert_seq_after (&mop->gsi, instr_seq, GSI_NEW_STMT);
      else
        gsi_insert_seq_before (&mop->gsi, instr_seq, GSI_SAME_STMT);
    }
}

/* Instruments all interesting memory accesses in the current function.  */

static void
instrument_mops (void)
{
  basic_block bb;
  int *blocks_inverted;
  struct bb_data *bb_data;
  struct bb_data *pred;
  struct bb_data *bbd;
  edge e;
  edge_iterator ei;
  int sb_line_min, sb_line_max;
  int cnt, i;

  /* The function does basic block traversal in reverse top sort order
     of the inverted CFG.  Such order is required to properly mark super-blocks.
     The idea behind super-blocks is as follows.
     If several memory accesses happen within SBLOCK_SIZE source code lines
     from each other, then we only mark the first access as SBLOCK.
     This allows the runtime library to memorize a stack trace
     only for the first access and do not memorize for others.
     This significantly reduces memory consumption in exchange for slightly
     imprecise stack traces for previous accesses.  */

  blocks_inverted = XNEWVEC (int, last_basic_block + NUM_FIXED_BLOCKS);
  bb_data = XCNEWVEC (struct bb_data, last_basic_block + NUM_FIXED_BLOCKS);
  cnt = inverted_post_order_compute (blocks_inverted);
  for (i = 0; i < cnt; i++)
    {
      bb = BASIC_BLOCK (blocks_inverted [i]);
      bbd = &bb_data [bb->index];
      /* Iterate over all predecessors and merge their sblock info.  */
      FOR_EACH_EDGE (e, ei, bb->preds)
        {
          pred = &bb_data [e->src->index];
          if (!pred->is_visited || !pred->has_sb || pred == bbd)
            {
              /* If there is a not visited predecessor,
                 or a predecessor with no active sblock info,
                 or a self-loop, then we will have to start
                 a brand new sblock on next memory access.  */
              bbd->has_sb = 0;
              break;
            }
          else if (bbd->has_sb == 0)
            {
              /* If it's a first predecessor, just copy the info.  */
              bbd->has_sb = 1;
              bbd->sb_file = pred->sb_file;
              bbd->sb_line_min = pred->sb_line_min;
              bbd->sb_line_max = pred->sb_line_max;
            }
          else
            {
              /* Otherwise, find the interception
                 between two sblock descriptors.  */
              bbd->has_sb = 0;
              if (bbd->sb_file != 0 && pred->sb_file != 0
                  && strcmp (bbd->sb_file, pred->sb_file) == 0)
                {
                  sb_line_min = MAX (bbd->sb_line_min, pred->sb_line_min);
                  sb_line_max = MIN (bbd->sb_line_max, pred->sb_line_max);
                  if (sb_line_min <= sb_line_max)
                    {
                      bbd->has_sb = 1;
                      bbd->sb_line_min = sb_line_min;
                      bbd->sb_line_max = sb_line_max;
                    }
                }
              /* No interception, have to start new sblock.  */
              if (bbd->has_sb == 0)
                break;
            }
        }

      instrument_bblock (bbd, bb);
      bbd->is_visited = 1;
    }

  free (blocks_inverted);
  free (bb_data);
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
  seq = build_func_entry_instr ();
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
      seq = build_func_exit_instr ();
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

  func_ignore = tsan_ignore ();
  if (func_ignore == tsan_ignore_func)
    return 0;

  func_calls = 0;
  func_mops = 0;

  push_gimplify_context (&gctx);

  instrument_mops ();

  if (is_func_instrumentation_required ())
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

