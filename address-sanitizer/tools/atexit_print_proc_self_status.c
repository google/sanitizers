#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

// At exit, print the contents of /proc/self/status tp proc_status.$pid.
// Build:
//  gcc atexit_print_proc_self_status.c -shared -fPIC -o  atexit_print_proc_self_status.so
// Use:
//  LD_PRELOAD=`pwd`/atexit_print_proc_self_status.so your-program

static void print_proc_self_status() {
  char buff[4096];
  FILE *status = fopen("/proc/self/status", "r");
  assert(status);
  sprintf(buff, "proc_status.%d", getpid());
  FILE *out = fopen(buff, "w");
  assert(out);
  fread(buff, 1, sizeof(buff), status);
  fprintf(out, "%s\b", buff);
  fclose(status);
  fclose(out);
}

__attribute__((constructor)) static void register_print_proc_self_status() {
  atexit(print_proc_self_status);
}
