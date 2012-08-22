#ifndef MSANDR_MSANDR_TEST_SO_H
#define MSANDR_MSANDR_TEST_SO_H

void dso_memfill(char* s, unsigned n);
int dso_callfn(int (*fn)(void));
int dso_callfn1(int (*fn)(long long, long long, long long));

#endif
