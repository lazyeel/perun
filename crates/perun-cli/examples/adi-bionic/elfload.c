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
#include <signal.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/stat.h>
#include <ucontext.h>
static void *REAL_VDFUT, *REAL_CVU;
static uint64_t tramp_vdfut(uint64_t,uint64_t,uint64_t,uint64_t);
static uint64_t tramp_cvu(uint64_t,uint64_t,uint64_t,uint64_t);

typedef struct {
    char name[96];
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
    const uint32_t *gnuhash;
} Lib;

static Lib g_libs[32];
static int g_nlibs;

// gdb cannot see these mappings -- they are ours, not the loader's -- so the
// loader attributes the fault itself. On aarch64 glibc mcontext_t is the
// legacy struct with __pc/__sp directly; there is no gregs[] and no REG_PC.
// gdb cannot see these mappings -- they are ours, not the loader's -- so the
// loader attributes the fault itself. On aarch64 glibc mcontext_t is the
// legacy struct with `pc` and `regs[]` directly; there is no gregs[].
//
// Everything here is write(2) on purpose. The Apple constructors have already
// left glibc complaining "invalid stdio handle", so printf inside a signal
// handler faults on the very thing it is trying to report; write is the only
// async-signal-safe option.
static void say(const char *s) { (void)!write(2, s, strlen(s)); }
static void sayhex(const char *tag, uint64_t v) {
    char b[80]; size_t n = 0;
    while (*tag) b[n++] = *tag++;
    b[n++] = '0'; b[n++] = 'x';
    int started = 0;
    for (int i = 15; i >= 0; i--) {
        int d = (int)((v >> (i * 4)) & 0xF);
        if (d || started || i == 0) { b[n++] = (char)(d < 10 ? '0' + d : 'a' + d - 10); started = 1; }
    }
    b[n++] = '\n';
    (void)!write(2, b, n);
}

static void on_abort(int sig, siginfo_t *si, void *uc_) {
    (void)sig;
    ucontext_t *uc = (ucontext_t *)uc_;
    uint64_t pc = (uint64_t)uc->uc_mcontext.pc;
    uint64_t lr = (uint64_t)uc->uc_mcontext.regs[30];
    say("[elfload] signal pc="); sayhex("", pc); say("\n");
    {
        /* The CFF computes its dispatch index from w0 (the first argument):
         *   eor w10, w0, w10 / and w9, w9, w0, lsl #1 / add w9, w10, w9
         * then does ldrsw x10, [x25, w9, uxtw #2]. If w9 is out of range the
         * table read is garbage and the computed jump lands nowhere. So the
         * question is what the engine actually passed. */
        uint64_t w0 = uc->uc_mcontext.regs[0] & 0xffffffffu;
        say("[elfload] w0(first arg)="); sayhex("", w0);
        say("  w1="); sayhex("", (uint64_t)uc->uc_mcontext.regs[1] & 0xffffffffu);
        say("  x8="); sayhex("", (uint64_t)uc->uc_mcontext.regs[8]);
        say("\n");
    }
    say("[elfload]   si_addr="); sayhex("", (uint64_t)(uintptr_t)si->si_addr);
    for (int i = 0; i < g_nlibs; i++) {
        Lib *L = &g_libs[i];
        if (pc >= (uint64_t)L->base && pc < (uint64_t)L->base + L->span) {
            say("[elfload]   in "); say(L->name);
            say("[elfload]   rva="); sayhex("", pc - (uint64_t)L->base);
            for (int j = 0; j < g_nlibs; j++)
                if (lr >= (uint64_t)g_libs[j].base && lr < (uint64_t)g_libs[j].base + g_libs[j].span) {
                    say("[elfload]   called from "); say(g_libs[j].name);
                    say("[elfload]   rva="); sayhex("", lr - (uint64_t)g_libs[j].base);
                }
            break;
        }
    }
    _exit(86);
}

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
// __sF is NOT a function. In legacy Bionic it is a DATA symbol holding the
// FILE* of the standard stream, and the Apple libraries hand it straight to
// fprintf/fwrite. A no-op function pointer here is what glibc rejects with
// "invalid stdio handle" and then aborts on -- so it has to be a real FILE*.
static FILE *sF(void) { return *(FILE **)dlsym(RTLD_DEFAULT, "stdout"); }
static int  stub_abort_msg(const char *m) { (void)m; return 0; }
static void stub_assert2(const char *f, int l, const char *a) { (void)f;(void)l;(void)a; abort(); }
static int  stub_errno(void) { return 0; }
// The last nine. All are Android-platform or fortify-surface symbols, and
// none is on the provisioning path: logging, the program name, the
// atfork hook list, and the __FD_*_chk wrappers glibc no longer exports
// under those names (its own are __fd_chk and friends).
static int  s_log_print(int prio, const char *tag, const char *fmt, ...) {
    (void)prio; (void)tag; (void)fmt; return 0;
}
static int  s_log_write(int prio, const char *tag, const char *msg) {
    (void)prio; (void)tag; (void)msg; return 0;
}
static const char *s_progname(void) { return "perun"; }
static int  s_atfork(void (*f)(void), void *a, void *d) { (void)f;(void)a;(void)d; return 0; }
static void s_fd_chk(int fd, int flags) { (void)fd; (void)flags; }
static void *bionic_stub2(const char *n) {
    if (!strcmp(n, "__android_log_print")) return (void *)s_log_print;
    if (!strcmp(n, "__android_log_write")) return (void *)s_log_write;
    if (!strcmp(n, "getprogname"))       return (void *)s_progname;
    if (!strcmp(n, "pthread_atfork"))     return (void *)s_atfork;
    if (!strcmp(n, "__FD_SET_chk"))      return (void *)s_fd_chk;
    if (!strcmp(n, "__FD_CLR_chk"))      return (void *)s_fd_chk;
    if (!strcmp(n, "__FD_ISSET_chk"))    return (void *)s_fd_chk;
    return NULL;
}
static int  stub_sysprop(const char *n, char *v, int m) { (void)n; if (v&&m>0) v[0]=0; return 0; }

// Bionic-only symbols, the residue glibc does not have. None of these is on a
// hot path for provisioning: __sF is a CFI alias target that is never called
// through, and the errno accessors abort rather than return.
// ── stdio interception ────────────────────────────────────────────────────
// Bionic and glibc disagree about FILE, so handing Apple's streams to glibc's
// stdio walks a structure that is not a glibc FILE: the fault is a small
// offset into a garbage pointer, which is exactly the si_addr=0x8 signature
// seen in libstoreservicescore's constructor. The ADI path has no reason to
// print, so every entry point here is inert. fopen is the exception: it must
// hand back a real glibc FILE* or the caller's NULL check fails and the code
// takes a different, more interesting path than the one we want to measure.
static FILE *s_fopen(const char *a, const char *b) { (void)b; return fopen(a ? a : "/dev/null", "r"); }
static int s_fclose(FILE *f) { (void)f; return 0; }
static int s_fprintf(FILE *f, const char *fmt, ...) { (void)f; (void)fmt; return 0; }
static int s_vfprintf(FILE *f, const char *fmt, va_list a) { (void)f; (void)fmt; (void)a; return 0; }
static int s_fflush(FILE *f) { (void)f; return 0; }
static int s_ferror(FILE *f) { (void)f; return 0; }
static int s_fileno(FILE *f) { (void)f; return -1; }
static int s_fseek(FILE *f, long o, int w) { (void)f; (void)o; (void)w; return 0; }
static long s_ftell(FILE *f) { (void)f; return -1; }
static size_t s_fread(void *p, size_t z, size_t n, FILE *f) { (void)p; (void)z; (void)n; (void)f; return 0; }
static size_t s_fwrite(const void *p, size_t z, size_t n, FILE *f) { (void)p; (void)f; return z * n; }
static int s_fputc(int c, FILE *f) { (void)c; (void)f; return 0; }
static int s_fputs(const char *s, FILE *f) { (void)s; (void)f; return 0; }
static int s_puts(const char *s) { (void)s; return 0; }


// The engine's LoadLibraryWithPath almost certainly dlopen()s its own
// CoreADI library rather than expecting the caller to have mapped it. There is
// no dynamic loader in this process, so dlopen is intercepted here and
// answered from the libraries already mapped. Logged, because "it dlopens
// nothing" would close this and "it dlopens libCoreADI.so" explains -45075.
static void say(const char *);
static void *find_export(const char *name);
static void *find_export(const char *);
static void *find_export_in(Lib *L, const char *name) {
    for (size_t i = 1; i < L->sym_n; i++) {
        if (!L->syms[i].st_name || !L->syms[i].st_shndx) continue;
        if (!strcmp(L->strs + L->syms[i].st_name, name))
            return L->base + (L->syms[i].st_value - L->lo);
    }
    return NULL;
}

static void *s_dlopen(const char *f, int fl) {
    (void)fl; say("[dl] dlopen "); say(f); say("\n");
    if (f) for (int i = 0; i < g_nlibs; i++)
        if (strstr(g_libs[i].name, f)) return g_libs[i].base;
    void *r = dlsym(RTLD_NEXT, "dlopen");
    return r ? ((void *(*)(const char *, int))r)(f, fl) : NULL;
}
static int   s_dlclose(void *h) { (void)h; return 0; }
// Must resolve against the loader's own tables. Forwarding to glibc's dlsym
// with a handle glibc never created returns NULL, and the engine then jumps
// through a null vdfut768ig -- the si_addr=0x0 seen before this was fixed.
static void *s_dlsym(void *h, const char *n) {
    say("[dl] dlsym "); say(n); say("\n");
    void *e = find_export(n);
    if (e && !strcmp(n, "vdfut768ig"))  { REAL_VDFUT = e; e = (void *)tramp_vdfut; }
    if (e && !strcmp(n, "cvu8io98wun")) { REAL_CVU   = e; e = (void *)tramp_cvu;   }
    say("[dl] dlsym "); say(n); say(" -> ");
    if (e) { sayhex("", (uint64_t)(uintptr_t)e); }
    else   { say("NULL\n"); }
    if (e) return e;
    for (int i = 0; i < g_nlibs; i++)
        if (g_libs[i].base == h) return find_export_in(&g_libs[i], n);
    return NULL;
}
static const char *s_dlerror(void) { return "elfload: dlopen intercepted"; }

static void *stdio_stub(const char *n) {
    if (!strcmp(n, "dlopen"))    return (void *)s_dlopen;
    if (!strcmp(n, "dlclose"))   return (void *)s_dlclose;
    if (!strcmp(n, "dlsym"))     return (void *)s_dlsym;
    if (!strcmp(n, "dlerror"))   return (void *)s_dlerror;
    if (!strcmp(n, "fopen"))     return (void *)s_fopen;
    if (!strcmp(n, "fclose"))    return (void *)s_fclose;
    if (!strcmp(n, "fprintf"))   return (void *)s_fprintf;
    if (!strcmp(n, "vfprintf"))  return (void *)s_vfprintf;
    if (!strcmp(n, "fflush"))    return (void *)s_fflush;
    if (!strcmp(n, "ferror"))    return (void *)s_ferror;
    if (!strcmp(n, "fileno"))    return (void *)s_fileno;
    if (!strcmp(n, "fseek"))     return (void *)s_fseek;
    if (!strcmp(n, "fseeko"))    return (void *)s_fseek;
    if (!strcmp(n, "ftell"))     return (void *)s_ftell;
    if (!strcmp(n, "ftello"))    return (void *)s_ftell;
    if (!strcmp(n, "fread"))     return (void *)s_fread;
    if (!strcmp(n, "fwrite"))    return (void *)s_fwrite;
    if (!strcmp(n, "fputc"))     return (void *)s_fputc;
    if (!strcmp(n, "fputs"))     return (void *)s_fputs;
    if (!strcmp(n, "puts"))      return (void *)s_puts;
    return NULL;
}



// Entry-argument trampoline.
//
// The fault is reported deep inside the flattened body, long after the
// dispatcher has clobbered every argument register, so the w0 read there is a
// CFF intermediate and not the caller's argument. This logs the four
// incoming registers and tail-calls the real entry, which is the only place
// the caller's arguments still exist.
static uint64_t tramp_vdfut(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3) {
    say("[entry] vdfut768ig  x0="); sayhex("", a0);
    say("  x1="); sayhex("", a1);
    say("  x2="); sayhex("", a2);
    say("  x3="); sayhex("", a3);
    say("  (real entry "); sayhex("", (uint64_t)(uintptr_t)REAL_VDFUT); say(")\n");
    return ((uint64_t (*)(uint64_t, uint64_t, uint64_t, uint64_t))REAL_VDFUT)(a0, a1, a2, a3);
}
static uint64_t tramp_cvu(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3) {
    say("[entry] cvu8io98wun x0="); sayhex("", a0);
    say("  x1="); sayhex("", a1);
    say("  x2="); sayhex("", a2);
    say("  x3="); sayhex("", a3); say("\n");
    return ((uint64_t (*)(uint64_t, uint64_t, uint64_t, uint64_t))REAL_CVU)(a0, a1, a2, a3);
}

static void *REAL_VDFUT, *REAL_CVU;
static uint64_t tramp_vdfut(uint64_t,uint64_t,uint64_t,uint64_t);
static uint64_t tramp_cvu(uint64_t,uint64_t,uint64_t,uint64_t);
static void *bionic_stub(const char *name) {
    { void *q = stdio_stub(name); if (q) return q; }
    if (!strcmp(name, "__sF")) return (void *)(uintptr_t)sF();
    if (!strcmp(name, "android_set_abort_message")) return (void *)(uintptr_t)stub_abort_msg;
    if (!strcmp(name, "__assert2")) return (void *)(uintptr_t)stub_assert2;
    if (!strcmp(name, "__get_h_errno")) return (void *)(uintptr_t)stub_errno;
    if (!strcmp(name, "__errno")) return (void *)(uintptr_t)&g_errno_slot;
    if (!strcmp(name, "__system_property_get")) return (void *)(uintptr_t)stub_sysprop;
    return NULL;
}
// A library built with .gnu.hash and no .hash has no DT_HASH, and nchain --
// the symbol count -- is derived from the hash table itself. Taking the count
// from DT_HASH alone silently yields zero, and the library then exports
// nothing. Every NDK system library is built this way, so libz/libm/... were
// invisible to symbol resolution.
static size_t gnu_hash_nchain(const uint32_t *h) {
    if (!h) return 0;
    uint32_t nbuckets   = h[0];
    uint32_t symoffset  = h[1];
    uint32_t bloom_size = h[2];
    if (!nbuckets || !bloom_size) return 0;
    /* header: nbuckets, symoffset, bloom_size, bloom_shift; then the bloom
       filter (bloom_size words), then nbuckets bucket words, then the chain. */
    const uint32_t *buckets = h + 4 + bloom_size;
    const uint32_t *chain   = buckets + nbuckets;
    uint32_t last = symoffset;
    for (uint32_t i = 0; i < nbuckets; i++)
        if (buckets[i] > last) last = buckets[i];
    if (last < symoffset) return symoffset;
    // The chain terminates at the first entry with bit0 set (HASH_VALUE).
    for (uint32_t j = last;; j++) {
        if (chain[j - symoffset] & 1u) return (size_t)j + 1;
    }
}

static size_t gnu_hash_nchain(const uint32_t *h);

// Symbol count from the section header table, not from DT_HASH.
//
// DT_HASH is absent from a GNU-hash-only build and DT_GNU_HASH makes the count
// depend on walking buckets and a hash chain, which is fragile. Every one of
// these libraries has a .dynsym section whose sh_size/sh_entsize is exact and
// needs no interpretation. Getting this wrong is silent: the loader maps the
// library, resolves nothing, and reports zero unresolved symbols because it
// never looked.
static void symtab_from_sections(Lib *L, const unsigned char *img, size_t img_sz) {
    if (img_sz < 64) return;
    uint64_t sh_off; memcpy(&sh_off, img + 0x28, 8);
    uint16_t sh_ent, sh_num;
    memcpy(&sh_ent, img + 0x3a, 2);
    memcpy(&sh_num, img + 0x3c, 2);
    if (!sh_off || !sh_num || sh_ent < 64) return;
    for (uint16_t i = 0; i < sh_num; i++) {
        uint64_t o = sh_off + (uint64_t)i * sh_ent;
        if (o + 64 > img_sz) return;
        uint32_t type;  memcpy(&type, img + o + 4, 4);
        if (type != 11) continue;                 /* SHT_DYNSYM */
        uint64_t off, size, ent;
        memcpy(&off,  img + o + 24, 8);
        memcpy(&size, img + o + 32, 8);
        memcpy(&ent,  img + o + 56, 8);
        if (!ent) return;
        L->sym_n = (size_t)(size / ent);
        if (!L->syms) L->syms = (Elf64_Sym *)(L->base + off);
        return;
    }
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
    if (!p) p = bionic_stub2(name);
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

    Lib *L = &g_libs[g_nlibs];
    snprintf(L->name, sizeof L->name, "%s", path);
    g_nlibs++;
    L->base = base; L->lo = lo; L->span = span; L->dyn = dyn;
    symtab_from_sections(L, img, (size_t)sz);
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
        case DT_GNU_HASH:
            /* No .hash at all in a GNU-hash-only library: fall back to it. */
            if (!L->sym_n) L->sym_n = gnu_hash_nchain((const uint32_t *)(base + (d->d_un.d_ptr - lo)));
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
                        if (fn) { printf("  init[%s] #%zu %p\n", L->name, k, (void *)fn); fflush(stdout); fn(); }
                    }
                }
        }
    }
}

// Resolve an exported symbol by name across the loaded Apple libraries.
static void *find_export(const char *name) {
    for (int i = 0; i < g_nlibs; i++) {
        Lib *L = &g_libs[i];
        for (size_t idx = 1; idx < L->sym_n; idx++) {
            if (!L->syms[idx].st_name || !L->syms[idx].st_shndx) continue;
            if (!strcmp(L->strs + L->syms[idx].st_name, name))
                return L->base + (L->syms[idx].st_value - L->lo);
        }
    }
    return NULL;
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: elfload <so>...\n"); return 2; }
    struct sigaction sa; memset(&sa,0,sizeof sa);
    sa.sa_sigaction = on_abort; sa.sa_flags = SA_SIGINFO;
    sigaction(SIGABRT, &sa, NULL);
    sigaction(SIGSEGV, &sa, NULL);
    int call_at = -1;
    for (int i = 1; i < argc; i++) if (!strcmp(argv[i], "--call")) { call_at = i; break; }
    int nlibs_arg = (call_at > 0) ? call_at : argc;
    for (int i = 1; i < nlibs_arg; i++) map_lib(argv[i]);
    for (int i = 0; i < g_nlibs; i++) relocate(&g_libs[i]);
    for (int i = 0; i < g_nlibs; i++) run_init(&g_libs[i]);
    printf("[elfload] done, %d libs\n", g_nlibs);

    if (call_at > 0 && call_at + 2 < argc) {
        /* "--call NAME DIR": after loading, drive the engine the way
         * adi_test.c does on Termux. */
        const char *dir = argv[call_at + 2];
        int (*load)(const char *) = (int (*)(const char *))find_export("kq56gsgHG6");
        int (*code)(int)       = (int (*)(int))find_export("aslgmuibau");
        if (!load || !code) { printf("[call] missing ADI exports\n"); return 3; }
        int (*setpath)(const char *) = (int (*)(const char *))find_export("nf92ngaK92");
        int (*setid)(const char *, unsigned) =
            (int (*)(const char *, unsigned))find_export("Sph98paBcz");
        int rc = load(dir);
        printf("[call] ADILoadLibraryWithPath(\"%s\") = %d\n", dir, rc);
        int c = code(-2);
        printf("[call] ADIGetLoginCode(-2) = %d  %s\n", c,
               c == 0 ? "(provisioned)" : c == -45061 ? "(not provisioned)" : "");
        if (setpath) {
            if (mkdir("/opt/data/adi-aarch64/adi-data", 0755) != 0 && errno != EEXIST) { /* ok */ }
            int p1 = setpath("/opt/data/adi-aarch64/adi-data");
            printf("[call] ADISetProvisioningPath = %d\n", p1);
        } else printf("[call] no SetProvisioningPath export\n");
        if (setid) {
            const char *cands[] = { "1a2b", "1a2b3c4d5e6f7081", NULL };
            for (int k = 0; cands[k]; k++) {
                int id = setid(cands[k], (unsigned)strlen(cands[k]));
                printf("[call] ADISetAndroidID(\"%s\") = %d\n", cands[k], id);
                if (id == 0) break;
            }
        } else printf("[call] no SetAndroidID export\n");
        int c2 = code(-2);
        printf("[call] ADIGetLoginCode(-2) after config = %d  %s\n", c2,
               c2 == 0 ? "(PROVISIONED)" : c2 == -45061 ? "(not provisioned)" : "");
    }
    return 0;
}
