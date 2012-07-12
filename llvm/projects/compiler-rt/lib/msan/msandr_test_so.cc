#include "msandr_test_so.h"

void dso_memfill(char* s, unsigned n) {
  for (unsigned i = 0; i < n; ++i)
    s[i] = i;
}

int dso_callfn(int (*fn)(void)) {
  return fn();
}
