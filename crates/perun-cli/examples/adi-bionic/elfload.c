// Minimal aarch64 ELF dynamic loader for the Apple CoreADI libraries.
//
// WHY THIS EXISTS. The libraries are Bionic-linked. On a Termux device the
// device's own Bionic runtime provides the LIBC version node and the ~118
// symbols under it, and everything works. On this host there is no Android
// userland, and the two obvious bridges both fail, measured:
//
//   * map the NDK's Bionic libc.so as a library  -> its constructors and its
//     malloc cross into a process whose loader and harness are glibc, and the
//     first Apple constructor dies with SIGSEGV;
//   * strip the version requirement (unversion.py) -> same collision, plus
//     the loader recurses and overflows its stack.
//
// So this loader does something narrower on purpose: it NEVER maps a Bionic
// libc. It maps only the Apple libraries, and resolves every undefined
// symbol against, in order:
//
//   1. the running glibc   (memcpy, pthread_rwlock_*, open, read, ...)
//   2. a table of Bionic-only stubs (__sF, __get_h_errno, ...)
//   3. dlsym, for anything else already in the process
//
// The NDK's libc.so is opened and parsed as a *dictionary* -- its .dynsym is
// read for the version-node structure only -- but it is never relocated or
// executed. That keeps exactly one allocator in the process: glibc's.
//
// Build:  aarch64-linux-gnu-gcc -O2 -o elfload elfload.c -ldl
// Run:    qemu-aarch64-static ./elfload <so> [so ...]
#include <elf.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <dlfcn.h>

typedef struct {
    unsigned char *base;
    uint64_t lo;
    size_t span;
    Elf64_Sym *syms;
    size_t sym_n;
    const char *strs;
    Elf64_Rela *rela;
    size_t rela_n;
    Elf64_Rela *jmprel;
    size_t jmprel_n;
    const Elf64_Dyn *dyn;
} Lib;

static Lib g_libs[32];
static int g_nlibs;

static void die(const char *m, const char *d) {
    fprintf(stderr, "[elfload] FATAL %s: %s\n", m, d ? d : "(null)");
    exit(1);
}

// Bionic exposes __errno as a TLS *variable* and the code takes its address
// (R_AARCH64_ABS64), so a function stub will not do -- there must be real
// storage behind the symbol. Single-threaded here, so a plain static is the
// correct shape; a threaded run would need a TLS slot.
static int g_errno_slot;
static void *stub_errno_addr(void) { return &g_errno_slot; }
static void stub_sF(void) {}
static int  stub_abort_msg(const char *m) { (void)m; return 0; }
static void stub_assert2(const char *f, int l, const char *a) { (void)f;(void)l;(void)a; abort(); }
static int  stub_errno(void) { return 0; }
static int  stub_sysprop(const char *n, char *v, int m) { (void)n; if (v&&m>0) v[0]=0; return 0; }

// Bionic-only symbols, the residue glibc does not have. None of these is on a
// hot path for provisioning: __sF is a CFI alias target that is never called
// through, and the errno accessors abort rather than return.
static void *bionic_stub(const char *name) {
    if (!strcmp(name, "__sF")) return (void *)(uintptr_t)stub_sF;
    if (!strcmp(name, "android_set_abort_message")) return (void *)(uintptr_t)stub_abort_msg;
    if (!strcmp(name, "__assert2")) return (void *)(uintptr_t)stub_assert2;
    if (!strcmp(name, "__get_h_errno")) return (void *)(uintptr_t)stub_errno;
    if (!strcmp(name, "__errno")) return (void *)(uintptr_t)&g_errno_slot;
    if (!strcmp(name, "__system_property_get")) return (void *)(uintptr_t)stub_sysprop;
    return NULL;
}
static void *find_in_loaded(const char *name) {
    for (int i = 0; i < g_nlibs; i++) {
        Lib *L = &g_libs[i];
        for (size_t idx = 1; idx < L->sym_n; idx++) {
            if (!L->syms[idx].st_name || !L->syms[idx].st_shndx) continue;
            const char *n = L->strs + L->syms[idx].st_name;
            if (!strcmp(n, name)) return L->base + (L->syms[idx].st_value - L->lo);
        }
    }
    return NULL;
}

static void *resolve(const char *name) {
    void *p = bionic_stub(name);
    if (p) return p;
    p = dlsym(RTLD_DEFAULT, name);
    if (p) return p;
    return find_in_loaded(name);
}

static void map_lib(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) die("open", path);
    off_t sz = lseek(fd, 0, SEEK_END);
    if (sz <= 0) die("size", path);
    unsigned char *img = mmap(NULL, (size_t)sz, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE, fd, 0);
    if (img == MAP_FAILED) die("mmap file", path);
    close(fd);

    Elf64_Ehdr *eh = (Elf64_Ehdr *)img;
    if (memcmp(eh->e_ident, ELFMAG, SELFMAG)) die("not an ELF", path);
    Elf64_Phdr *ph = (Elf64_Phdr *)(img + eh->e_phoff);

    // Reserve one contiguous span covering every PT_LOAD, then copy in.
    uint64_t lo = UINT64_MAX, hi = 0;
    for (int i = 0; i < eh->e_phnum; i++) {
        if (ph[i].p_type != PT_LOAD) continue;
        if (ph[i].p_vaddr < lo) lo = ph[i].p_vaddr;
        if (ph[i].p_vaddr + ph[i].p_memsz > hi) hi = ph[i].p_vaddr + ph[i].p_memsz;
    }
    size_t span = (size_t)((hi - lo + 0xFFF) & ~0xFFFULL);
    unsigned char *base = mmap(NULL, span, PROT_READ | PROT_WRITE | PROT_EXEC,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED) die("mmap span", path);

    for (int i = 0; i < eh->e_phnum; i++) {
        if (ph[i].p_type != PT_LOAD) continue;
        memcpy(base + (ph[i].p_vaddr - lo), img + ph[i].p_offset, ph[i].p_filesz);
        if (ph[i].p_memsz > ph[i].p_filesz)
            memset(base + (ph[i].p_vaddr - lo) + ph[i].p_filesz, 0,
                   ph[i].p_memsz - ph[i].p_filesz);
    }

    Elf64_Dyn *dyn = NULL;
    for (int i = 0; i < eh->e_phnum; i++) {
        if (ph[i].p_type == PT_DYNAMIC)
            dyn = (Elf64_Dyn *)(base + (ph[i].p_vaddr - lo));
    }
    if (!dyn) die("no PT_DYNAMIC", path);

    Lib *L = &g_libs[g_nlibs++];
    L->base = base; L->lo = lo; L->span = span; L->dyn = dyn;
    for (Elf64_Dyn *d = dyn; d->d_tag; d++) {
        switch (d->d_tag) {
        case DT_SYMTAB: L->syms = (Elf64_Sym *)(base + (d->d_un.d_ptr - lo)); break;
        case DT_HASH: {
            /* nchain is the symbol count; walking only relocation-referenced
               symbols misses every exported definition, which is how operator
               new/delete and the whole libc++abi surface went unresolved. */
            unsigned int *h = (unsigned int *)(base + (d->d_un.d_ptr - lo));
            L->sym_n = h[1];
            break;
        }
        case DT_STRTAB: L->strs = (const char *)(base + (d->d_un.d_ptr - lo)); break;
        case DT_RELA:   L->rela = (Elf64_Rela *)(base + (d->d_un.d_ptr - lo)); break;
        case DT_RELASZ: L->rela_n = d->d_un.d_val / sizeof(Elf64_Rela); break;
        case DT_JMPREL: L->jmprel = (Elf64_Rela *)(base + (d->d_un.d_ptr - lo)); break;
        case DT_PLTRELSZ: L->jmprel_n = d->d_un.d_val / sizeof(Elf64_Rela); break;
        default: break;
        }
    }
    printf("  mapped %-34s base=%p span=%#zx rela=%zu jmprel=%zu\n",
           path, (void *)base, span, L->rela_n, L->jmprel_n);
    fflush(stdout);
}

static void relocate(Lib *L) {
    Elf64_Rela *all = L->rela;
    size_t n = L->rela_n;
    for (size_t i = 0; i < n; i++) {
        uint32_t type = (uint32_t)(all[i].r_info & 0xFFFFFFFF);
        uint32_t idx  = (uint32_t)(all[i].r_info >> 32);
        uint64_t *slot = (uint64_t *)(L->base + (uint64_t)all[i].r_offset);
        if (type == R_AARCH64_RELATIVE) { *slot = (uint64_t)L->base + all[i].r_addend; continue; }
        if (type == R_AARCH64_ABS64 || type == R_AARCH64_GLOB_DAT ||
            type == R_AARCH64_JUMP_SLOT) {
            const char *nm = (idx && L->syms[idx].st_name) ? L->strs + L->syms[idx].st_name : "";
            void *t = resolve(nm);
            if (!t) { printf("  UNRESOLVED %s (type %u)\n", nm, type); continue; }
            *slot = (uint64_t)t;
        }
    }
    for (size_t i = 0; i < L->jmprel_n; i++) {
        uint32_t type = (uint32_t)(L->jmprel[i].r_info & 0xFFFFFFFF);
        uint32_t idx  = (uint32_t)(L->jmprel[i].r_info >> 32);
        uint64_t *slot = (uint64_t *)(L->base + (uint64_t)L->jmprel[i].r_offset);
        if (type == R_AARCH64_RELATIVE) { *slot = (uint64_t)L->base + L->jmprel[i].r_addend; continue; }
        const char *nm = (idx && L->syms[idx].st_name) ? L->strs + L->syms[idx].st_name : "";
        void *t = resolve(nm);
        if (!t) { printf("  UNRESOLVED-JMP %s\n", nm); continue; }
        *slot = (uint64_t)t;
    }
}

static void run_init(Lib *L) {
    for (const Elf64_Dyn *d = L->dyn; d->d_tag; d++) {
        if (d->d_tag == DT_INIT_ARRAY) {
            Elf64_Addr *a = (Elf64_Addr *)(L->base + (d->d_un.d_ptr - L->lo));
            // size is not in .dynamic; read DT_INIT_ARRAYSZ if present
            for (const Elf64_Dyn *e = L->dyn; e->d_tag; e++)
                if (e->d_tag == DT_INIT_ARRAYSZ) {
                    size_t n = e->d_un.d_val / sizeof(Elf64_Addr);
                    for (size_t k = 0; k < n; k++) {
                        void (*fn)(void) = (void (*)(void))a[k];
                        if (fn) { printf("  init[%zu] %p\n", k, (void *)fn); fn(); }
                    }
                }
        }
    }
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: elfload <so>...\n"); return 2; }
    for (int i = 1; i < argc; i++) map_lib(argv[i]);
    for (int i = 0; i < g_nlibs; i++) relocate(&g_libs[i]);
    for (int i = 0; i < g_nlibs; i++) run_init(&g_libs[i]);
    printf("[elfload] done, %d libs\n", g_nlibs);
    return 0;
}
