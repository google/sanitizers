#include "msandr_test_so.h"

void my_memfill(char* s, unsigned n) {
  for (unsigned i = 0; i < n; ++i)
    s[i] = i;
}
