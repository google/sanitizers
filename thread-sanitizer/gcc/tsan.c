/* GCC instrumentation plugin for ThreadSanitizer
 * Copyright (c) 2011, Google Inc. All rights reserved.
 * Author: Dmitry Vyukov (dvyukov)
 *
 * IT is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3, or (at your option) any later
 * version. See http://www.gnu.org/licenses/
 */

/*
//TODO(dvyukov): handle inlining wrt ignore files:
// for each mop check actual source location

//TODO(dvyukov): create a makefile

//TODO(dvyukov): collect per-function stats

//TODO(dvyukov): support loop-wide sblocks

//TODO(dvyukov): eliminate excessive aliasing mops

//TODO(dvyukov): create specialized tsan_rtl_mop: r/w, sblock, size

//TODO(dvyukov): move all shadow stack support code into callee function

//TODO(dvyukov): check induced reads/writes:
// int g = 0;
// for (int i = 0; i != N; i += 1)
//   if (X[i]) g += 1;

//TODO(dvyukov): if it's a call to a known function (malloc/free) ->
// do not start new sblock

//TODO(dvyukov): try to not instrument first write to a local var:
// int x = 1; // even if 'x' is addressable, initialization can't race
// at least eliminate stores to const variables

//TODO(dvyukov): handle instrumentation of ADDR_EXPR
*/

#include <plugin.h>
#include <plugin-version.h>
#include <config.h>
#include <system.h>
#include <coretypes.h>
#include <tm.h>
#include <tree-pass.h>
#include <function.h>
#include <gimple.h>
#include <diagnostic.h>
#include <stdio.h>

int plugin_is_GPL_compatible = 1;
extern struct gimple_opt_pass pass_tsan;
int flag_tsan;
const char *flag_tsan_ignore;

#if 1
static void
finish_unit (void *gcc_data, void *user_data)
{
  static int finished;

  (void) gcc_data;
  (void) user_data;

  if (finished++)
    return;
  extern void tsan_finish_file (void);
  tsan_finish_file ();
}
#endif

int
plugin_init (struct plugin_name_args* info, struct plugin_gcc_version* ver)
{
  struct register_pass_info pass;
  int i;

  if (strcmp (ver->basever, gcc_version.basever) != 0)
    {
      printf ("tsan: invalid gcc version (expected/actual: %s/%s)\n",
             gcc_version.basever, ver->basever);
      exit(1);
    }

  flag_tsan = 1;
  for (i = 0; i < info->argc; i++)
    {
      if (strcmp (info->argv[i].key, "ignore") == 0)
        flag_tsan_ignore = xstrdup (info->argv[i].value);
    }

  pass.pass = &pass_tsan.pass;
  pass.reference_pass_name = "loop";
  pass.ref_pass_instance_number = 1;
  pass.pos_op = PASS_POS_INSERT_BEFORE;
  register_callback(info->base_name, PLUGIN_PASS_MANAGER_SETUP, NULL, &pass);
  register_callback(info->base_name, PLUGIN_ALL_PASSES_END, finish_unit, NULL);
  return 0;
}

