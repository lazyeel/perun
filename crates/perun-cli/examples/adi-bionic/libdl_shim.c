// Bionic-shaped libdl.so for the Apple libraries, on top of aarch64 glibc.
//
// The Apple .so files ask for "libdl.so" by its Bionic name and, like
// libCoreADI.so, require the version node "LIBC". Pointing the name at the
// real glibc libdl.so.2 fails with `version `LIBC' not found`: the loader
// checks the already-loaded objects in order, finds glibc's libdl first, and
// that object has no LIBC node -- so it never reaches a shim that does.
//
// This shim carries the LIBC node and forwards the dl* entry points. Each
// resolved symbol keeps its real function-pointer type; a `void *` slot cannot
// hold one, and assigning it is what the compiler rejects.

#define _GNU_SOURCE
#include <dlfcn.h>
#include <link.h>
#include <stddef.h>

void *dlopen(const char *f, int fl) {
    static void *(*p)(const char *, int);
    if (!p) p = dlsym(RTLD_NEXT, "dlopen");
    return p(f, fl);
}

int dlclose(void *h) {
    static int (*p)(void *);
    if (!p) p = dlsym(RTLD_NEXT, "dlclose");
    return p(h);
}

void *dlsym(void *h, const char *s) {
    static void *(*p)(void *, const char *);
    if (!p) p = dlsym(RTLD_NEXT, "dlsym");
    return p(h, s);
}

char *dlerror(void) {
    static char *(*p)(void);
    if (!p) p = dlsym(RTLD_NEXT, "dlerror");
    return p();
}

int dladdr(const void *addr, Dl_info *out) {
    static int (*p)(const void *, Dl_info *);
    if (!p) p = dlsym(RTLD_NEXT, "dladdr");
    return p(addr, out);
}

int dl_iterate_phdr(int (*cb)(struct dl_phdr_info *, size_t, void *), void *d) {
    static int (*p)(int (*)(struct dl_phdr_info *, size_t, void *), void *);
    if (!p) p = dlsym(RTLD_NEXT, "dl_iterate_phdr");
    return p(cb, d);
}
