/* GCC instrumentation plugin for ThreadSanitizer.
 * Copyright (c) 2012, Google Inc. All rights reserved.
 * Author: Dmitry Vyukov (dvyukov)
 *
 * IT is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3, or (at your option) any later
 * version. See http://www.gnu.org/licenses/
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
int flag_tsan = 1;

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

int
plugin_init (struct plugin_name_args* info, struct plugin_gcc_version* ver)
{
  struct register_pass_info pass;

  if (strcmp (ver->basever, gcc_version.basever) != 0)
    {
      printf ("tsan: invalid gcc version (expected/actual: %s/%s)\n",
             gcc_version.basever, ver->basever);
      exit(1);
    }

  pass.pass = &pass_tsan.pass;
  pass.reference_pass_name = "loop";
  pass.ref_pass_instance_number = 1;
  pass.pos_op = PASS_POS_INSERT_BEFORE;
  register_callback(info->base_name, PLUGIN_PASS_MANAGER_SETUP, NULL, &pass);
  register_callback(info->base_name, PLUGIN_ALL_PASSES_END, finish_unit, NULL);
  return 0;
}
