// A Bionic-shaped libc.so for libCoreADI.so, on top of real aarch64 glibc.
//
// libCoreADI.so is linked against Bionic and requires a version node named
// "LIBC", which aarch64 glibc does not define, so the loader refuses the
// object before running anything:
//
//     dlopen: .../libc.so.6: version `LIBC' not found
//
// This library defines that node and re-exports, under it, exactly the
// symbols libCoreADI.so imports from libc. Each body forwards to the real
// glibc implementation found through dlsym(RTLD_NEXT, ...), so behaviour is
// glibc's -- the shim exists to satisfy the loader, not to change semantics.
//
// The 23 symbols are the complete undefined-import list of libCoreADI.so
// minus __system_property_get (Android-specific, provided by liblog.so) and
// arc4random (glibc 2.36+ has it natively, forwarded here for uniformity).
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdarg.h>
#include <fcntl.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>

static void *next(const char *n) { return dlsym(RTLD_NEXT, n); }

// Liveness marker: proves at run time that the guest resolves these symbols
// through THIS shim, so a trace showing no calls means "no file access
// happened", not "the shim was bypassed".
__attribute__((constructor)) static void shim_alive(void) {
    fprintf(stderr, "[adi-fs] SHIM_ALIVE pid=%d\n", (int)getpid());
    fflush(stderr);
}

// Path tracing. strace is unusable in this container -- ptrace(PTRACE_TRACEME)
// is denied, so a syscall trace comes back empty and reads as "the guest
// touched no files", which would be a false negative. Wrapping the libc
// entry points libCoreADI.so actually imports shows the provisioning walk from
// inside the emulated process instead, with no privileges needed.
static int trace_fs = -1;
static void note(const char *fn, const char *path) {
    if (trace_fs < 0) { trace_fs = getenv("ADI_FS_TRACE") ? 1 : 0; }
    if (!trace_fs) { return; }
    fprintf(stderr, "[adi-fs] %s(%s)\n", fn, path ? path : "(null)");
    fflush(stderr);
}

void *malloc(size_t n) {
    static void *(*f)(size_t);
    if (!f) { f = next("malloc"); }
    return f(n);
}

void free(void *p) {
    static void (*f)(void *);
    if (!f) { f = next("free"); }
    f(p);
}

int open(const char *p, int fl, ...) {
    static int (*f)(const char *, int, mode_t);
    va_list ap;
    if (!f) { f = next("open"); }
    note("open", p);
    mode_t m = 0;
    if (fl & O_CREAT) { va_start(ap, fl); m = va_arg(ap, int); va_end(ap); }
    return f(p, fl, m);
}

int close(int fd) {
    static int (*f)(int);
    if (!f) { f = next("close"); }
    return f(fd);
}

ssize_t read(int fd, void *b, size_t n) {
    static ssize_t (*f)(int, void *, size_t);
    if (!f) { f = next("read"); }
    return f(fd, b, n);
}

ssize_t write(int fd, const void *b, size_t n) {
    static ssize_t (*f)(int, const void *, size_t);
    if (!f) { f = next("write"); }
    return f(fd, b, n);
}

int fstat(int fd, struct stat *st) {
    static int (*f)(int, struct stat *);
    if (!f) { f = next("fstat"); }
    return f(fd, st);
}

int lstat(const char *p, struct stat *st) {
    static int (*f)(const char *, struct stat *);
    if (!f) { f = next("lstat"); }
    note("lstat", p);
    return f(p, st);
}

int chmod(const char *p, mode_t m) {
    static int (*f)(const char *, mode_t);
    if (!f) { f = next("chmod"); }
    note("chmod", p);
    return f(p, m);
}

int mkdir(const char *p, mode_t m) {
    static int (*f)(const char *, mode_t);
    if (!f) { f = next("mkdir"); }
    note("mkdir", p);
    return f(p, m);
}

int ftruncate(int fd, off_t n) {
    static int (*f)(int, off_t);
    if (!f) { f = next("ftruncate"); }
    return f(fd, n);
}

mode_t umask(mode_t m) {
    static mode_t (*f)(mode_t);
    if (!f) { f = next("umask"); }
    return f(m);
}

char *strncpy(char *d, const char *s, size_t n) {
    static char *(*f)(char *, const char *, size_t);
    if (!f) { f = next("strncpy"); }
    return f(d, s, n);
}

int gettimeofday(struct timeval *tv, void *tz) {
    static int (*f)(struct timeval *, void *);
    if (!f) { f = next("gettimeofday"); }
    return f(tv, tz);
}

uint32_t arc4random(void) {
    static uint32_t (*f)(void);
    if (!f) { f = next("arc4random"); }
    return f();
}

int pthread_rwlock_init(pthread_rwlock_t *l, const pthread_rwlockattr_t *a) {
    static int (*f)(pthread_rwlock_t *, const pthread_rwlockattr_t *);
    if (!f) { f = next("pthread_rwlock_init"); }
    return f(l, a);
}

int pthread_rwlock_destroy(pthread_rwlock_t *l) {
    static int (*f)(pthread_rwlock_t *);
    if (!f) { f = next("pthread_rwlock_destroy"); }
    return f(l);
}

int pthread_rwlock_rdlock(pthread_rwlock_t *l) {
    static int (*f)(pthread_rwlock_t *);
    if (!f) { f = next("pthread_rwlock_rdlock"); }
    return f(l);
}

int pthread_rwlock_wrlock(pthread_rwlock_t *l) {
    static int (*f)(pthread_rwlock_t *);
    if (!f) { f = next("pthread_rwlock_wrlock"); }
    return f(l);
}

int pthread_rwlock_unlock(pthread_rwlock_t *l) {
    static int (*f)(pthread_rwlock_t *);
    if (!f) { f = next("pthread_rwlock_unlock"); }
    return f(l);
}

int __cxa_atexit(void (*f)(void *), void *a, void *d) {
    static int (*g)(void (*)(void *), void *, void *);
    if (!g) { g = next("__cxa_atexit"); }
    return g(f, a, d);
}

void __cxa_finalize(void *d) {
    static void (*f)(void *);
    if (!f) { f = next("__cxa_finalize"); }
    f(d);
}

int *__errno(void) {
    static int *(*f)(void);
    if (!f) { f = next("__errno_location"); }
    return f();
}
