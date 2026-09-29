// Dump the arguments the Android engine passes to vdfut768ig and to the three
// classic provisioning entry points around it.
//
// libstoreservicescore.so is the caller. This captures the calls by swapping the
// function pointers the library itself stores, not by patching its code, and
// there is no dlsym interception of any kind: no override of dlsym, no
// RTLD_NEXT, no re-implementation of the loader's lookup.
//
// ── why pointer swapping, and how the addresses were found ────────────────
//
// The caller resolves the two CoreADI entry points with plain dlsym calls and
// stores each result in a global. The static view (objdump over .text, matching
// rip-relative operands against the .got slots) locates all of it:
//
//   1ddd8d: mov  -0x108(%rbp),%rdi     ; the handle from the earlier dlopen
//   1ddd94: mov  0x73d45(%rip),%rsi    ; rsi -> 0x251ae0
//   1ddd9b: call dlsym@plt
//   1ddda0: mov  %rax,0x77a79(%rip)    ; -> 0x255820  (vdfut768ig)
//   1dddef: mov  0x73cf2(%rip),%rsi    ; rsi -> 0x251ae8
//   1dddf6: call dlsym@plt
//   1dddfb: mov  %rax,0x77a16(%rip)    ; -> 0x255818  (cvu8io98wun)
//
// The two .got slots hold pointers to the name strings, established by
// R_X86_64_RELATIVE relocations in .rela.dyn whose addends are 0x90c20
// ("vdfut768ig") and 0x91260 ("cvu8io98wun").
//
// The surrounding code is control-flow-flattened -- every basic block ends in
// `jmp *reg` through a jump table -- so the dlsym calls are interleaved with
// dispatcher arithmetic and objdump renders the block starts as (bad). The
// flattening does not matter here, because the value we want is not in the
// instruction stream at all: it is in a global the loader fills in before the
// dispatcher ever runs. Rewriting that one global is enough.
//
// Patching the code instead does not work, and the reason is worth recording.
// vdfut768ig's prologue folds rbp into a magic constant
// (`movabs $0xdac212dead40676a,%rax; lea (%rax,%rbp,1),%rcx`) and uses it to
// index a CFF table, so a trampoline that replays the prologue at a different
// address computes a different index and the function jumps to a displacement
// off a garbage base. Even a naked stub that tail-jumps without a frame of its
// own did not survive: the fault landed in an anonymous mapping 0x4ef9000 bytes
// from the trampoline, with no dlsym override and no STUB-entered trace, i.e.
// the dispatcher had already consumed the state. Swapping the pointer keeps
// every byte of Apple's code exactly where it was.

#define _GNU_SOURCE
#include <dlfcn.h>
#include <elf.h>
#include <errno.h>
#include <link.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

// The vaddrs above, for the 4.9.6 build in libs/ (Apple Music, x86_64).
#define VDFUT_PTR_VADDR 0x255820u
#define CVU_PTR_VADDR   0x255818u
#define VDFUT_NAME_VADDR 0x90c20u

// ── the load base of libstoreservicescore.so ────────────────────────────────
//
// The base is the address at which the segment with file offset 0 is mapped.
// The lowest mapping of the file is not the same thing, and using it puts every
// computed address out by the page offset.
static const char *g_libdir;

static const char *path_of(const char *name) {
    static char buf[1024];
    char needle[512];
    snprintf(needle, sizeof needle, "/%s", name);
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return NULL;
    char line[2048];
    const char *found = NULL;
    while (fgets(line, sizeof line, f)) {
        if (!strstr(line, needle)) continue;
        unsigned long long lo, off;
        char perms[8] = {0};
        if (sscanf(line, "%llx-%*llx %7s %llx", &lo, perms, &off) < 3) continue;
        if (off != 0) continue;
        char *last = strrchr(line, ' ');
        if (!last) continue;
        snprintf(buf, sizeof buf, "%s", last + 1);
        found = buf;
        break;
    }
    fclose(f);
    return found;
}

static uint64_t base_of(const char *name) {
    const char *p = path_of(name);
    if (!p) return 0;
    unsigned long long lo, off;
    char perms[8] = {0};
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return 0;
    char line[2048];
    uint64_t base = 0;
    while (fgets(line, sizeof line, f)) {
        if (!strstr(line, p)) continue;
        if (sscanf(line, "%llx-%*llx %7s %llx", &lo, perms, &off) < 3) continue;
        if (off != 0) continue;
        base = lo;
        break;
    }
    fclose(f);
    return base;
}

// ── .dynsym, read from the file ────────────────────────────────────────────
//
// elfload.c's technique: the section headers are not mapped, so the symbol
// table is read from the file and the addresses come from the load base. The
// dynamic tags are not usable on their own -- in libCoreADI.so DT_SYMTAB is the
// SYSV __dso_handle stub at 0x33a8 while .dynsym is at 0x49f40 -- and the
// loader's own dl_iterate_phdr does not list these two Apple libraries at all,
// though both are fully mapped.

static int slurp(const char *path, unsigned char **out, size_t *out_sz) {
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    if (fseek(f, 0, SEEK_END)) { fclose(f); return 0; }
    long n = ftell(f);
    if (n <= 0) { fclose(f); return 0; }
    rewind(f);
    unsigned char *buf = malloc((size_t)n);
    if (!buf) { fclose(f); return 0; }
    size_t got = fread(buf, 1, (size_t)n, f);
    fclose(f);
    if (got != (size_t)n) { free(buf); return 0; }
    *out = buf;
    *out_sz = got;
    return 1;
}

static void *resolve_in(const char *dir, const char *obj, const char *sym) {
    char path[1024];
    snprintf(path, sizeof path, "%s/%s", dir, obj);
    uint64_t base = base_of(obj);
    if (!base) return NULL;
    unsigned char *img = NULL;
    size_t sz = 0;
    if (!slurp(path, &img, &sz)) return NULL;

    uint64_t sh_off, shstrtab = 0, syms_addr = 0, strs_addr = 0;
    uint16_t sh_ent, sh_num, sh_strndx;
    size_t sym_n = 0;
    memcpy(&sh_off, img + 0x28, 8);
    memcpy(&sh_ent, img + 0x3a, 2);
    memcpy(&sh_num, img + 0x3c, 2);
    memcpy(&sh_strndx, img + 0x3e, 2);
    // The section table ends exactly at end of file in these objects, so the
    // bounds test has to be ">=", and the name table has to be resolved before
    // any name is compared.
    if (sh_off && sh_num && sh_ent >= 64 && sh_strndx < sh_num) {
        uint64_t so = sh_off + (uint64_t)sh_strndx * sh_ent;
        if (so + 64 <= sz) memcpy(&shstrtab, img + so + 24, 8);
    }
    for (uint16_t i = 0; sh_off && shstrtab && i < sh_num; i++) {
        uint64_t o = sh_off + (uint64_t)i * sh_ent;
        if (o + 64 > sz) break;
        uint32_t type;
        memcpy(&type, img + o + 4, 4);
        uint64_t addr, ssz, ent;
        memcpy(&addr, img + o + 16, 8);
        uint32_t no;
        memcpy(&no, img + o, 4);
        const char *nm = (const char *)img + shstrtab + no;
        if (type == 11) { /* SHT_DYNSYM */
            memcpy(&ssz, img + o + 32, 8);
            memcpy(&ent, img + o + 56, 8);
            if (ent) { syms_addr = addr; sym_n = (size_t)(ssz / ent); }
        } else if (type == 3 && !strcmp(nm, ".dynstr")) {
            strs_addr = addr;
        }
    }
    free(img);
    if (!syms_addr || !strs_addr || !sym_n) return NULL;

    const unsigned char *sy = (const unsigned char *)(base + syms_addr);
    const char *st = (const char *)(base + strs_addr);
    for (size_t k = 1; k < sym_n; k++) {
        uint32_t st_name;
        uint16_t st_shndx;
        uint64_t st_value;
        memcpy(&st_name, sy + k * sizeof(ElfW(Sym)), 4);
        memcpy(&st_shndx, sy + k * sizeof(ElfW(Sym)) + 6, 2);
        memcpy(&st_value, sy + k * sizeof(ElfW(Sym)) + 8, 8);
        if (!st_name || !st_shndx) continue;
        if (strcmp(st + st_name, sym)) continue;
        return (void *)(base + st_value);
    }
    return NULL;
}

// ── dumping ────────────────────────────────────────────────────────────────

static int readable(const void *p) {
    uintptr_t a = (uintptr_t)p;
    uintptr_t start = a & ~(uintptr_t)4095;
    unsigned char vec[1];
    if (mincore((void *)start, (a - start) + 1, vec) != 0) return 0;
    return (vec[0] & 1) != 0;
}

static void dump(const char *tag, uint64_t addr, int n) {
    if (addr < 0x1000) {
        printf("    %-5s 0x%016lx  (not a pointer)\n", tag, (unsigned long)addr);
        return;
    }
    if (!readable((const void *)addr)) {
        printf("    %-5s 0x%016lx  (unreadable)\n", tag, (unsigned long)addr);
        return;
    }
    const unsigned char *p = (const unsigned char *)addr;
    printf("    %-5s 0x%016lx\n", tag, (unsigned long)addr);
    for (int i = 0; i < n; i += 16) {
        printf("      +0x%02x  ", i);
        for (int j = 0; j < 16; j++) printf("%02x ", p[i + j]);
        printf(" |");
        for (int j = 0; j < 16; j++)
            printf("%c", (p[i + j] >= 32 && p[i + j] < 127) ? p[i + j] : '.');
        printf("|\n");
    }
}

static const char *phase = "(none yet)";

static void report(const char *what, uint64_t a0, uint64_t a1, uint64_t a2,
                   uint64_t a3) {
    printf("\n================ %s ================\n", what);
    printf("    arg0=0x%016lx  arg1=0x%016lx  arg2=0x%016lx  arg3=0x%016lx\n",
           (unsigned long)a0, (unsigned long)a1, (unsigned long)a2,
           (unsigned long)a3);
    dump("arg0", a0, 64);
    dump("arg1", a1, 96);
    dump("arg2", a2, 96);
    dump("arg3", a3, 64);
    fflush(stdout);
}

// The four wrappers. These have ordinary C frames, which is safe here: they are
// entered through a function pointer the dispatcher calls, not through a
// relocated prologue, so nothing about their frame geometry is visible to the
// obfuscated code that called them.
// Build it with the engine, as a separate target:
//
//   $CC -O2 -Wall -DDUMP_ADI=1 -I curl_inc -I openssl_inc \
//       -o adi_dump adi_test.c dump_adi.c libs/libcurl.so -ldl -lc
//
// adi_test.c calls dump_init() under #ifdef DUMP_ADI, after the load that
// populates the globals. Without that define the file is not compiled in and the
// engine behaves exactly as it does in run-native.sh.

typedef int (*adi4_fn)(uint64_t, uint64_t, uint64_t, uint64_t);

static adi4_fn real_vdfut;
static adi4_fn real_cvu;

// cvu8io98wun takes one output buffer, not a frame. The Windows build returns
// 0 for it and that changes nothing downstream, which is measured; what was
// never established is what a working caller puts in that buffer, or whether
// the buffer it hands in is the one the dispatcher later reads. So the dump
// brackets the call: the 64 bytes at *arg0 before, the same 64 after, and the
// return value, which is the whole question in one place.
static int wrap_cvu(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3) {
    const char *prev = phase;
    phase = "cvu8io98wun";
    report("cvu8io98wun", a0, a1, a2, a3);

    uint64_t buf = (a0 >= 0x1000) ? *(uint64_t *)a0 : 0;
    unsigned char before[64], after[64];
    int got = 0;
    if (buf && readable((void *)buf)) {
        memcpy(before, (const void *)buf, sizeof before);
        got = 1;
    }
    printf("    *arg0 = %#018lx  %s\n", (unsigned long)buf,
           got ? "(snapshotted 64 bytes before)" : "(not a readable pointer)");

    int rc = real_cvu ? real_cvu(a0, a1, a2, a3) : -1;

    printf("    --- what cvu8io98wun wrote to *arg0 ---\n");
    if (got && readable((void *)buf)) {
        memcpy(after, (const void *)buf, sizeof after);
        if (memcmp(before, after, sizeof before) == 0) {
            printf("    unchanged: the 64 bytes at *arg0 are identical after the call\n");
        } else {
            printf("    before:");
            for (int i = 0; i < 64; i++) printf(" %02x", before[i]);
            printf("\n    after :");
            for (int i = 0; i < 64; i++) printf(" %02x", after[i]);
            printf("\n    changed bytes: %d\n", ({
                int n = 0;
                for (int i = 0; i < 64; i++) if (before[i] != after[i]) n++;
                n;
            }));
        }
    } else {
        printf("    not sampled\n");
    }
    printf("    -> rc=%d\n", rc);
    fflush(stdout);
    phase = prev;
    return rc;
}

// ── post-call diff ──────────────────────────────────────────────────────────
//
// The 96 bytes at arg1 are the caller's live frame, and the token is not in
// them -- the only thing that changed between the two GetLoginCode calls was a
// heap pointer that moved. So: snapshot the regions before the call, snapshot
// them again after, and report what the library actually wrote. The frame's
// first words are themselves stack addresses (arg1+0x00 points 0x58 bytes below
// arg1; arg1+0x20 holds arg1 itself in the GetLoginCode case), so the buffer
// that receives the token is plausibly one or two hops past the frame.

#define SNAP_N 512
#define INDIR_N 256
#define NREGION 4

struct region {
    const char *name;
    uint64_t addr;
    int len;
    unsigned char before[SNAP_N];
    unsigned char after[SNAP_N];
    int ok;
};

static void snap(struct region *r) {
    r->ok = 0;
    if (!r->addr || r->addr < 0x1000) return;
    if (!readable((const void *)r->addr)) return;
    memcpy(r->before, (const void *)r->addr, r->len);
    r->ok = 1;
}

static void diff_region(struct region *r) {
    int n = 0;
    for (int i = 0; i < r->len; i++)
        if (r->before[i] != r->after[i]) n++;
    printf("    region %-10s @%#018lx  changed bytes: %d\n", r->name,
           (unsigned long)r->addr, n);
    for (int i = 0; i < r->len; i += 16) {
        int differs = 0;
        for (int j = 0; j < 16 && i + j < r->len; j++)
            if (r->before[i + j] != r->after[i + j]) differs = 1;
        if (!differs) continue;
        printf("      +0x%02x  after:", i);
        for (int j = 0; j < 16 && i + j < r->len; j++)
            printf(" %02x", r->after[i + j]);
        printf("\n              before:");
        for (int j = 0; j < 16 && i + j < r->len; j++)
            printf(" %02x", r->before[i + j]);
        printf("\n");
    }
    fflush(stdout);
}

// The X-Apple-I-MD framing: 00 00 00 05 | 00 00 00 10 | <16-byte body> |
// 00 00 00 04. The body rotates per token, so the fixed parts are what gets
// searched for; that works for whatever token this run produced.
static const unsigned char TOK_HDR[8] = {0, 0, 0, 5, 0, 0, 0, 0x10};
static const unsigned char TOK_TAIL[4] = {0, 0, 0, 4};

static void hunt_token(struct region *r) {
    for (int i = 0; i + 28 <= r->len; i++) {
        if (memcmp(r->after + i, TOK_HDR, 8)) continue;
        if (memcmp(r->after + i + 24, TOK_TAIL, 4)) continue;
        printf("    >>> TOKEN in %s at +0x%02x (abs %#018lx): ", r->name, i,
               (unsigned long)(r->addr + i));
        for (int j = 0; j < 28; j++) printf("%02x", r->after[i + j]);
        printf("\n");
        fflush(stdout);
    }
}

// ── payload capture ─────────────────────────────────────────────────────────
//
// The Windows-side work has run on a synthetic frame with a synthetic header
// since the start, and every hypothesis about -45020 rests on that. These three
// calls are the ones that carry a real payload from the working engine, so the
// bytes are worth keeping exactly rather than as a hex line in a log.
//
// The length is arg1[+8] and the buffer is *arg1, which is the shape the
// ordered dump shows; the header is the first four bytes and is the part most
// likely to be wrong in a reconstruction.

#define PAYLOAD_DIR "/opt/data/apk/x86"
static int payload_len(uint64_t frame) {
    if (!frame) return 0;
    return (int)*(uint32_t *)(frame + 8);
}

static const char *payload_path(uint64_t op) {
    if (op == 0xb0eda7afULL) return PAYLOAD_DIR "/payload_init.bin";
    if (op == 0xcfe0b46aULL) return PAYLOAD_DIR "/payload_prov.bin";
    return NULL;
}

// Call 1 and call 5 share an opcode, so the path carries the call number and
// the caller passes it; otherwise one would overwrite the other. Built by
// splitting at the last '/' rather than by scanning for '.', because the
// directory names here contain no dot but the base does and the earlier
// version conflated the two.
static int save_payload_n(uint64_t op, uint64_t frame, int callno) {
    const char *base = payload_path(op);
    if (!base || !frame) return 0;
    int len = payload_len(frame);
    if (len <= 0 || len > (1 << 20)) return 0;
    uint64_t buf = *(uint64_t *)frame;
    if (!buf) return 0;
    char path[256];
    if (callno > 0) {
        const char *dot = strrchr(base, '.');
        int stem = dot ? (int)(dot - base) : (int)strlen(base);
        snprintf(path, sizeof path, "%.*s_%d%s", stem, base, callno, dot ? dot : "");
    } else {
        snprintf(path, sizeof path, "%s", base);
    }
    FILE *f = fopen(path, "wb");
    if (!f) {
        printf("    [payload] cannot write %s: %s\n", path, strerror(errno));
        return 0;
    }
    size_t n = fwrite((const void *)buf, 1, (size_t)len, f);
    fclose(f);
    printf("    [payload] wrote %s (%zu bytes)\n", path, n);
    return n == (size_t)len;
}

static int payload_seen;

static int save_payload(uint64_t op, uint64_t frame) {
    if (!payload_path(op)) return 0;
    int n = ++payload_seen;
    return save_payload_n(op, frame, payload_path(op) && op == 0xb0eda7afULL ? n : 0);
}

static int wrap_vdfut(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3) {
    const char *prev = phase;
    phase = "vdfut768ig";
    report("vdfut768ig", a0, a1, a2, a3);

    // Keep the exact bytes of the caller's payload for the three calls that
    // carry real ones. A synthetic frame with a synthetic header has been the
    // basis of every Windows-side hypothesis so far, and the first question
    // worth answering with data is what the working engine actually passes.
    save_payload(a0, a1);

    // Deep dump of the caller's ctx. The frame is 96 bytes and eight of its
    // slots are host pointers; whether they are buffers, strings or numbers is
    // not visible from the frame alone, and guessing has cost this project
    // more than one round.
    {
        uint64_t *p = (uint64_t *)a1;
        if (a1 && readable((void *)a1)) {
            printf("    === DEEP DUMP CTX (%s) ===\n", phase);
            for (int i = 0; i < 12; i++) {
                uint64_t v = p[i];
                printf("    ctx[+0x%02x] = 0x%016lx\n", i * 8, (unsigned long)v);
                if (v > 0x10000 && v < 0x800000000000 && readable((void *)v)) {
                    unsigned char *t = (unsigned char *)v;
                    printf("      -> ");
                    for (int k = 0; k < 16; k++) printf("%02x ", t[k]);
                    printf(" |");
                    for (int k = 0; k < 16; k++)
                        putchar(t[k] >= 0x20 && t[k] < 0x7f ? t[k] : '.');
                    printf("|\n");
                }
            }
        }
    }

    struct region r[NREGION];
    memset(r, 0, sizeof r);
    r[0].name = "arg1";     r[0].addr = a1;                    r[0].len = SNAP_N;
    r[1].name = "*[arg1+0]"; r[1].addr = *(uint64_t *)(a1 + 0x00); r[1].len = INDIR_N;
    r[2].name = "*[arg1+20]"; r[2].addr = *(uint64_t *)(a1 + 0x20); r[2].len = INDIR_N;
    r[3].name = "*[arg1+08]"; r[3].addr = *(uint64_t *)(a1 + 0x08); r[3].len = INDIR_N;
    for (int i = 0; i < NREGION; i++) {
        snap(&r[i]);
        if (!r[i].ok)
            printf("    region %-10s @%#018lx  (not sampled: not a readable pointer)\n",
                   r[i].name, (unsigned long)r[i].addr);
    }

    int rc = real_vdfut ? real_vdfut(a0, a1, a2, a3) : -1;

    for (int i = 0; i < NREGION; i++)
        if (r[i].ok) memcpy(r[i].after, (const void *)r[i].addr, r[i].len);

    printf("\n    --- post-call diff, opcode %#010x ---\n", (unsigned)a0);
    for (int i = 0; i < NREGION; i++) if (r[i].ok) diff_region(&r[i]);
    for (int i = 0; i < NREGION; i++) if (r[i].ok) hunt_token(&r[i]);

    printf("    -> rc=%d\n", rc);
    fflush(stdout);
    phase = prev;
    return rc;
}

// ── pointer swapping ────────────────────────────────────────────────────────

static int swap(uint64_t base, uint64_t vaddr, void *wrapper, const char *what) {
    uint64_t *slot = (uint64_t *)(base + vaddr);
    if (!readable(slot)) {
        fprintf(stderr, "[dump] %s: slot %p not readable\n", what, (void *)slot);
        return 0;
    }
    long page = sysconf(_SC_PAGESIZE);
    uintptr_t p = (uintptr_t)slot & ~(uintptr_t)(page - 1);
    if (mprotect((void *)p, page, PROT_READ | PROT_WRITE)) {
        fprintf(stderr, "[dump] %s: mprotect: %s\n", what, strerror(errno));
        return 0;
    }
    void *prev = (void *)*slot;
    *slot = (uint64_t)(uintptr_t)wrapper;
    printf("[dump] swapped %-12s slot=%p %p -> %p\n", what, (void *)slot, prev,
           wrapper);
    fflush(stdout);
    return 1;
}

// Called by the harness after ADILoadLibraryWithPath has run and populated the
// globals, and before any provisioning entry point is called.
int dump_init(const char *libdir) {
    g_libdir = libdir;
    uint64_t base = base_of("libstoreservicescore.so");
    if (!base) {
        fprintf(stderr, "[dump] libstoreservicescore.so not mapped\n");
        return 0;
    }
    printf("[dump] libstoreservicescore.so base=%p\n", (void *)base);

    // Read the current value of the vdfut768ig slot first: the real pointer, to
    // call once the arguments have been recorded.
    uint64_t *vslot = (uint64_t *)(base + VDFUT_PTR_VADDR);
    real_vdfut = (adi4_fn)(void *)*vslot;
    printf("[dump] vdfut768ig slot %p currently holds %p\n", (void *)vslot,
           (void *)real_vdfut);

    int ok = 1;
    ok &= swap(base, VDFUT_PTR_VADDR, (void *)wrap_vdfut, "vdfut768ig");

    // cvu8io98wun used to be left alone on the grounds that it runs before
    // provisioning and that corrupting it was not worth the risk. That is a
    // risk note, not a measurement, and it left the one entry whose Windows
    // behaviour was unknown undumped. The swap is the same one the
    // vdfut768ig slot already takes -- a single store into a writable GOT
    // slot, no symbol resolution anywhere -- so the risk it was avoiding was
    // never the real one.
    uint64_t *cslot = (uint64_t *)(base + CVU_PTR_VADDR);
    real_cvu = (adi4_fn)(void *)*cslot;
    printf("[dump] cvu8io98wun slot %p currently holds %p\n", (void *)cslot,
           (void *)real_cvu);
    ok &= swap(base, CVU_PTR_VADDR, (void *)wrap_cvu, "cvu8io98wun");

    (void)VDFUT_NAME_VADDR;
    printf("[dump] init %s\n", ok ? "complete" : "INCOMPLETE");
    fflush(stdout);
    return ok;
}

// Resolves a symbol the same way, for a follow-up probe.
void *dump_resolve(const char *obj, const char *sym) {
    return resolve_in(g_libdir, obj, sym);
}
