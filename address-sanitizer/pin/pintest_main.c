#include <stdlib.h>
#include <string.h>
#include <stdio.h>
extern long Use(long *a);

int main(int argc, char **argv) {
  long *x = malloc(10 * sizeof(long));
  printf("Using %p\n", x + 11);
  // x[argc*11] = 1;
  Use(x + 11);
  free(x);
  return 0;
}
