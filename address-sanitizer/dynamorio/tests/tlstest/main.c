#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
extern long Use(long *a);

void* thread_procedure(void *arg) {
  long *x = (long*)arg + 11;
  printf("Using %p\n", x);
  Use(x);
  return NULL;
}

int main(int argc, char **argv) {
  long *x = malloc(10 * sizeof(long));
  pthread_t thr;
  pthread_create(&thr, NULL, thread_procedure, x);
  pthread_join(thr, NULL);
  free(x);
  return 0;
}
