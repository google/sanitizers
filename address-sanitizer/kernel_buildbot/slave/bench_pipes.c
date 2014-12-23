#include <unistd.h>
#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <pthread.h>


static int npipes = 1;
static int niters = 1;


void *do_pipes(void* unused);

int main(int argc, char **argv) {
	int nthreads = 1;
	pthread_t *threads;
	pthread_attr_t attr;
	int rc = 0;
	int i;

	npipes = atoi(argv[1]);
	if (argc >= 3) 
		niters = atoi(argv[2]);
	if (argc >= 4)
		nthreads = atoi(argv[3]);
	
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
	threads = malloc(sizeof(pthread_t) * nthreads);
	for (i = 0; i < nthreads; i++) {
		rc = pthread_create(&threads[i], &attr, &do_pipes, NULL);
		if (rc) {
			printf("Couldn't start thread. error %d\n", rc);
			return -1;	
		}
	}
	pthread_attr_destroy(&attr);
	for (i = 0; i < nthreads; i++) {
		rc = pthread_join(threads[i], NULL);
		if (rc) {
			printf("Couldn't join thread. error %d\n", rc);
			return -1;	
		}
	}
	free(threads);
	pthread_exit(NULL);
}

void *do_pipes(void* unused) {
	int* pipes;
	int i,j;
	char c = 'a';
	pipes = malloc(sizeof(int) * npipes * 2);
	for (j = 0; j < niters; ++j) {
		for (i = 0; i < npipes; ++i) {
			if (pipe(&pipes[i * 2])) {
				perror("Couldn't open pipe");
				free(pipes);
				exit(-1);
			}
		//	write(pipes[i * 2 + 1], &c, 1);
		}
		for (i = 0; i < npipes; ++i) {
		//	read(pipes[i * 2], &c, 1);
			close(pipes[i * 2]);
			close(pipes[i * 2 + 1]);
		}
	}
	free(pipes);
	pthread_exit(unused);
}
