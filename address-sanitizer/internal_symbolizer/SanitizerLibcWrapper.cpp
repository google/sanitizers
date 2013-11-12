#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

namespace __sanitizer {
int internal_open(const char *filename, int flags);
int internal_open(const char *filename, int flags, unsigned mode);
int internal_close(int fd);
int internal_stat(const char *path, void *buf);
int internal_lstat(const char *path, void *buf);
int internal_fstat(int fd, void *buf);
size_t internal_strlen(const char *s);
void *internal_mmap(void *addr, unsigned long length, int prot, int flags,
                    int fd, unsigned long long offset);
void *internal_memcpy(void *dest, const void *src, unsigned long n);
}  // namespace __sanitizer

// C-style interface around internal sanitizer libc functions.
extern "C" {

int open(const char *filename, int flags, ...) {
  if (flags | O_CREAT) {
    va_list va;
    va_start(va, flags);
    unsigned mode = va_arg(va, unsigned);
    va_end(va);
    return __sanitizer::internal_open(filename, flags, mode);
  }
  return __sanitizer::internal_open(filename, flags);
}

int close(int fd) { return __sanitizer::internal_close(fd); }

#define STAT(func, arg, buf)                                 \
  return __sanitizer::internal_##func(arg, buf);

int stat(const char *path, struct stat *buf) {
  STAT(stat, path, buf);
}

int lstat(const char *path, struct stat *buf) {
  STAT(lstat, path, buf);
}

int fstat(int fd, struct stat *buf) {
  STAT(fstat, fd, buf);
}

// Redirect versioned stat functions to the __sanitizer::internal() as well.
int __xstat(int version, const char *path, struct stat *buf) {
  STAT(stat, path, buf);
}

int __lxstat(int version, const char *path, struct stat *buf) {
  STAT(lstat, path, buf);
}

int __fxstat(int version, int fd, struct stat *buf) {
  STAT(fstat, fd, buf);
}

size_t strlen(const char *s) { return __sanitizer::internal_strlen(s); }

void *mmap(void *addr, size_t length, int prot, int flags, int fd,
           off_t offset) {
  return __sanitizer::internal_mmap(addr, (unsigned long) length, prot, flags,
                                    fd, (unsigned long long) offset);
}

// Redirect some functions to sanitizer interceptors.

ssize_t __interceptor_read(int fd, void *ptr, size_t count);
ssize_t __interceptor_pread(int fd, void *ptr, size_t count, off_t offset);
ssize_t __interceptor_pread64(int fd, void *ptr, size_t count, off64_t offset);
char *__interceptor_realpath(const char *path, char *resolved_path);
int __interceptor_pthread_cond_broadcast(void *c);
int __interceptor_pthread_cond_wait(void *c, void *m);
int __interceptor_pthread_mutex_lock(void *m);
int __interceptor_pthread_mutex_unlock(void *m);

ssize_t read(int fd, void *ptr, size_t count) {
  return __interceptor_read(fd, ptr, count);
}
ssize_t pread(int fd, void *ptr, size_t count, off_t offset) {
  return __interceptor_pread(fd, ptr, count, offset);
}
ssize_t pread64(int fd, void *ptr, size_t count, off64_t offset) {
  return __interceptor_pread64(fd, ptr, count, offset);
}
char *realpath(const char *path, char *resolved_path) {
  return __interceptor_realpath(path, resolved_path);
}
int pthread_cond_broadcast(void *c) {
  return __interceptor_pthread_cond_broadcast(c);
}
int pthread_cond_wait(void *c, void *m) {
  return __interceptor_pthread_cond_wait(c, m);
}
int pthread_mutex_lock(void *m) {
  return __interceptor_pthread_mutex_lock(m);
}
int pthread_mutex_unlock(void *m) {
  return __interceptor_pthread_mutex_unlock(m);
}

}  // extern "C"

