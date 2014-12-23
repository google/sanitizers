#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <pthread.h>

#define IOV_MAX 1024

static int niters = 1;
static char *filename;

static void check(int result, char *message) {
	if (result < 0) {
		perror(message);
		exit(-1);
	}
}

void *do_bench(void *unused) 
{
	int i, j;
	int fd;
	struct iovec iov[IOV_MAX];
	char buf[IOV_MAX];
	off_t length;
	
	fd = open(filename, O_RDONLY);
	check(fd, "Couldn't open file");
	length = lseek(fd, 0, SEEK_END);
	check(length, "Seek failed");
	
	if (length > IOV_MAX)
		length = IOV_MAX;
	for (i = 0; i < length; ++i) {
		iov[i].iov_base = buf + (i * 31 % IOV_MAX);
		iov[i].iov_len = 1;
	}
	for (i = 0; i < niters; ++i) {
		check(preadv(fd, iov, length, 0), "Readv failed");
	}
	check(close(fd), "close failed");
	pthread_exit(unused);
}



int main(int argc, char **argv) {
	int nthreads = 1;
	pthread_t *threads;
	pthread_attr_t attr;
	int rc = 0;
	int i;

	filename = argv[1];
	if (argc >= 3) 
		niters = atoi(argv[2]);
	if (argc >= 4)
		nthreads = atoi(argv[3]);
	
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
	threads = malloc(sizeof(pthread_t) * nthreads);
	for (i = 0; i < nthreads; i++) {
		rc = pthread_create(&threads[i], &attr, &do_bench, NULL);
		if (rc) {
			printf("Couldn't start thread. error %d\n", rc);
			return -1;	
			cleanup();
		}
	}
	pthread_attr_destroy(&attr);
	for (i = 0; i < nthreads; i++) {
		rc = pthread_join(threads[i], NULL);
		if (rc) {
			printf("Couldn't join thread. error %d\n", rc);
			return -1;	
			cleanup();
		}
	}
	free(threads);
	pthread_exit(NULL);
}
