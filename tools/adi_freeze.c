/*
 * adi_freeze -- native ptrace entropy/time freezer for the Bionic ADI harness.
 *
 * WHY. Fixed-input offline replays still drift (~207/276 CPIM bytes) because only
 * gettimeofday was ever frozen. A causal test must control every candidate source
 * and PROVE each control fired: "observe site hits, do not assume them"
 * (RESEARCH.md 2026-11-11, review 2026-11-16). This tool spawns the target under
 * ptrace and, at every syscall boundary, rewrites the answers of the sources it
 * is asked to freeze, reporting a per-source hit counter at exit so a zero-hit
 * freeze can never be mistaken for a controlled source.
 *
 * Sources handled (x86_64):
 *   getrandom(318)        -> deterministic byte stream
 *   open/openat of /dev/urandom or /dev/random -> tracked fd;
 *   read/pread64 on that fd -> deterministic byte stream
 *   clock_gettime(228)    -> fixed CLOCK_REALTIME (monotonic only with --freeze-monotonic)
 *   gettimeofday(96)      -> fixed realtime
 *   time(201)             -> fixed realtime
 *   getpid(39)/gettid(186)-> fixed values
 *   vDSO                  -> AT_SYSINFO_EHDR zeroed in the child auxv at the
 *                            execve stop, so Bionic cannot serve clock reads
 *                            invisibly from userspace; syscalls then surface.
 *   AT_RANDOM (auxv)      -> the 16 kernel-provided bytes the loader hands to
 *                            libc for stack canaries/arc4random seeding are
 *                            overwritten with the deterministic stream.
 *
 * BISECTION SWITCHES. --no-rng leaves entropy live; --no-clock leaves time
 * live; freeze one at a time to attribute drift to a specific source.
 *
 * NOT frozen by default (deliberately): CLOCK_MONOTONIC* and
 * nanosleep/clock_nanosleep -- relative sleeps must stay real so repeat probes
 * still span wall time; freezing REALTIME only avoids absolute-time waits that
 * would otherwise spin (pthread_cond_timedwait on a frozen clock).
 *
 * Deterministic streams: --rng-hex / --urandom-hex fill buffers by repeating the
 * given bytes (default 32 x 0xA5). The bytes themselves matter less than being
 * constant across runs and != a plausible all-zero special case.
 *
 * Usage:
 *   adi_freeze [--epoch=N] [--rng-hex=HEX] [--urandom-hex=HEX]
 *              [--pid=N] [--tid=N] [--keep-vdso] [--freeze-monotonic]
 *              [--no-aslr] [--quiet] -- PROG [ARGS...]
 *
 * On child exit prints one JSON line to stderr:
 *   {"adi_freeze":{"epoch":...,"rng":{"hits":N,"bytes":N},
 *    "urandom":{"hits":N,"bytes":N},"clock_gettime":{"hits":N},
 *    "gettimeofday":{"hits":N},"time":{"hits":N},"getpid":{"hits":N},
 *    "gettid":{"hits":N},"vdso":"disabled|kept","aslr":"off|on"}}
 *
 * Exit status is the child's.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/personality.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef PTRACE_EVENT_EXIT
#define PTRACE_EVENT_EXIT 11
#endif
#ifndef PTRACE_EVENT_CLONE
#define PTRACE_EVENT_CLONE 3
#endif
#ifndef PTRACE_O_EXITKILL
#define PTRACE_O_EXITKILL (1 << 20)
#endif
#ifndef PTRACE_O_TRACEFORK
#define PTRACE_O_TRACEFORK (1 << 1)
#endif
#ifndef PTRACE_O_TRACEVFORK
#define PTRACE_O_TRACEVFORK (1 << 2)
#endif
#define PTRACE_O_TRACESYSGOOD 1

#define SYS_read           0
#define SYS_open           2
#define SYS_close          3
#define SYS_getpid         39
#define SYS_pread64        17
#define SYS_gettimeofday   96
#define SYS_time           201
#define SYS_gettid         186
#define SYS_openat         257
#define SYS_clock_gettime  228
#define SYS_getrandom      318
#define SYS_dup            32
#define SYS_dup2           33
#define SYS_dup3           292
#define SYS_write          1
#define SYS_pwrite64       18
#define SYS_lseek          8
#define SYS_ftruncate      77
#define SYS_rename         82
#define SYS_unlink         87
#define SYS_unlinkat       263
#define SYS_exit_group     231

#define AT_SYSINFO_EHDR    33
#define AT_RANDOM          25
#define CLOCK_REALTIME     0

#define MAX_PID_SLOTS 256

/* ---- OTP output write watchpoint ------------------------------------------- */
/* The engine's 16-byte OTP payload lives at otp+8 .. otp+24 (rcx at entry).
 * Hardware write watchpoints (DR0/DR1, 8 bytes each) catch the exact store
 * instructions even though the batch trace logs no memory operands. Debug
 * registers are per-thread; only the calling thread is armed. */
static int wp_on;                 /* one active watchpoint set per traced run */
static unsigned long wp_ptrvar;   /* address of the otp* variable ([rcx] at entry) */
static unsigned long wp_payload;  /* discovered buffer address + 8 */

/* arm DR0/DR1/DR2 once the buffer address is known */
static void wp_watch_payload(pid_t pid, unsigned long payload) {
    ptrace(PTRACE_POKEUSER, pid, (void *)offsetof(struct user, u_debugreg[0]),
           (void *)payload);
    ptrace(PTRACE_POKEUSER, pid, (void *)offsetof(struct user, u_debugreg[1]),
           (void *)(payload + 8));
    ptrace(PTRACE_POKEUSER, pid, (void *)offsetof(struct user, u_debugreg[2]),
           (void *)(payload + 16));
    wp_payload = payload;
    fprintf(stderr, "[trace] OTP payload watch at %lx..%lx\n",
            payload, payload + 24);
}

static void wp_arm(pid_t pid, unsigned long ptrvar) {
    /* DR0/DR1/DR2: 8-byte WRITE watchpoints covering payload+0..+24.
     * DR3: write watchpoint on the otp* variable itself: the engine
     * allocates the buffer inside the call, so at entry *otp is still NULL.
     * DR7: Ln=1, RWn=01 (write), LENn=11 (8 bytes) for every slot. */
    unsigned long dr7 = (1UL << 0) | (1UL << 16) | (3UL << 18) |
                        (1UL << 2) | (1UL << 20) | (3UL << 22) |
                        (1UL << 4) | (1UL << 24) | (3UL << 26) |
                        (1UL << 6) | (1UL << 28) | (3UL << 30);
    wp_ptrvar = ptrvar;
    ptrace(PTRACE_POKEUSER, pid,
           (void *)offsetof(struct user, u_debugreg[6]), 0);   /* clear sticky */
    if (ptrace(PTRACE_POKEUSER, pid, (void *)offsetof(struct user, u_debugreg[3]),
               (void *)wp_ptrvar) < 0 ||
        ptrace(PTRACE_POKEUSER, pid, (void *)offsetof(struct user, u_debugreg[7]),
               (void *)dr7) < 0)
        return;
    wp_on = 1;
    fprintf(stderr, "[trace] OTP ptr-var watchpoint armed at %lx (dr7=%lx)\n",
            wp_ptrvar, dr7);
}

static void wp_disarm(pid_t pid) {
    if (!wp_on) return;
    ptrace(PTRACE_POKEUSER, pid, (void *)offsetof(struct user, u_debugreg[7]), 0);
    wp_on = 0;
}

/* returns 1 when a watched PAYLOAD store has just executed (DR6 bits 0..2) */
static int wp_check(pid_t pid) {
    if (!wp_on) return 0;
    errno = 0;
    long dr6 = ptrace(PTRACE_PEEKUSER, pid,
                      (void *)offsetof(struct user, u_debugreg[6]), 0);
    if (errno != 0) return 0;
    if (dr6 & 15) {
        if (getenv("ADI_FREEZE_DEBUG_WP"))
            fprintf(stderr, "[wp] dr6=%lx payload=%lx\n",
                    (unsigned long)dr6, wp_payload);
        if (dr6 & 8) {
            /* the engine just stored the allocated buffer address in *otp */
            errno = 0;
            long optr = ptrace(PTRACE_PEEKDATA, pid, wp_ptrvar, 0);
            if (errno == 0 && optr > 0x10000)
                wp_watch_payload(pid, (unsigned long)optr + 8);
        }
        /* sticky DR6 bits suppress further #DB generation: clear all of them */
        ptrace(PTRACE_POKEUSER, pid,
               (void *)offsetof(struct user, u_debugreg[6]), 0);
    }
    return (dr6 & 7) != 0;
}

/* ---- whole-function batch trace mode -------------------------------------- */
/*
 * --trace-lib=NAME --trace-rva=0x... --trace-out=FILE:
 * resolve the library base from /proc/<pid>/maps once the child opens the
 * library, plant a one-shot INT3 at base+rva (the export entry), and from that
 * stop switch to PTRACE_SINGLESTEP, logging (ip, regs) per instruction until
 * the call returns (ip == the return address captured at entry) or the step
 * cap is hit. Freeze rewriting stays active during the traced call, so traced
 * runs reproduce the same frozen-epoch outputs as the plain frozen runs.
 *
 * Record (little-endian, sequential):
 *   u64 ip; u64 rax,rbx,rcx,rdx,rsi,rdi,rbp,rsp,r8..r15 (15 regs);
 *   u64 orig_rax; u8 kind (1=entry, 2=step, 3=returned, 4=cap-hit)
 */
static struct {
    const char *lib_name;
    unsigned long rva;
    const char *out_path;
    unsigned long long max_steps;
    int requested;
    int lib_seen;             /* child opened the library */
    unsigned long base;       /* runtime base of the first lib mapping */
    unsigned long patch_addr; /* base + rva */
    int patched;
    int done;                 /* trace finished: never arm or reopen again */
    unsigned char orig_byte;
    FILE *out;
    unsigned long long steps;
    unsigned long retaddr;
    int tracing;
    char file_path[256];      /* library path as seen in maps */
    int no_xstate;            /* --trace-noxs: GPR-only records */
    int no_rec;               /* --trace-norec: call log only, no step file */
    const char *calls_path;   /* --call-log: compact call/ret stream */
    FILE *calls;
} trc;

/* --trace-dump-arg/--trace-dump-ret: dump memory at a register-relative
 * address at the traced entry / return. This is how the internal state
 * serializer is sampled without a multi-gigabyte step trace. */
struct reg_dump { int reg; long long off; int deref; unsigned long long size; char tag[160]; };
static struct reg_dump rd_arg[8], rd_ret[8];
static int nrd_arg, nrd_ret;

struct trec {
    unsigned long long ip;
    unsigned long long r[16];   /* rax rbx rcx rdx rsi rdi rbp rsp r8..r15 */
    unsigned long long orig_rax;
    unsigned int tid;           /* which thread executed the step */
    unsigned char kind;
};

/* ---- RDTSC freeze ---------------------------------------------------------- */
/* The engine reads the raw timestamp counter directly (0f 31 rdtsc at
 * libstoreservicescore RVA 0x1c6419 on this rig): a userspace instruction no
 * syscall freezer can see, whose value demonstrably feeds the traced warm-OTP
 * dataflow. While tracing, every step stop checks the instruction just
 * executed and, if it was rdtsc/rdtscp, rewrites the returned counter with a
 * deterministic fake clock: base + reads*step. An unverified or uncontrolled
 * time source has already bitten once (vDSO); TSC is the same class of bug. */
static struct {
    unsigned long long base;   /* counter value at the first rewrite */
    unsigned long long step;   /* advance per read */
    unsigned long long reads;  /* rewrites performed */
    unsigned long long cur;    /* next value to hand out */
    int enabled;
} tscc;

/* full XSAVE area per record (XMM/YMM and friends; the engine's data flow is
 * heavily SIMD and GP registers alone provably do not capture the OTP
 * computation). Layout of the blob is whatever the kernel returns for
 * NT_X86_XSTATE; the analyser reads XMM at offset 576..832 when present. */
#ifndef NT_X86_XSTATE
#define NT_X86_XSTATE 0x202
#endif
static size_t xs_len;                 /* discovered on the first record */
static unsigned char xs_buf[4096];

static void trace_capture_xstate(pid_t pid) {
    struct iovec iov = { xs_buf, sizeof xs_buf };
    if (ptrace(PTRACE_GETREGSET, pid, (void *)(unsigned long)NT_X86_XSTATE, &iov) < 0) {
        xs_len = 0;
        return;
    }
    if (!xs_len) xs_len = iov.iov_len;
}

static void trace_write(pid_t pid, struct user_regs_struct *r, unsigned char kind) {
    if (!trc.out || trc.no_rec) return;
    struct trec t;
    memset(&t, 0, sizeof t);
    t.ip = r->rip;
    unsigned long long regs[16] = { r->rax, r->rbx, r->rcx, r->rdx, r->rsi, r->rdi,
                                    r->rbp, r->rsp, r->r8, r->r9, r->r10, r->r11,
                                    r->r12, r->r13, r->r14, r->r15 };
    memcpy(t.r, regs, sizeof regs);
    t.orig_rax = (unsigned long long)r->orig_rax;
    t.tid = (unsigned int)pid;
    t.kind = kind;
    fwrite(&t, sizeof t, 1, trc.out);
    if (trc.no_xstate) return;
    trace_capture_xstate(pid);
    if (xs_len) fwrite(xs_buf, 1, xs_len, trc.out);
}

/* find runtime bases of a library by name in /proc/<pid>/maps: every mapping
 * whose path ends with the given name is a candidate; the real load base is
 * the one where the runtime byte at +rva equals the FILE byte at rva
 * (Bionic's linker may expose transient or secondary mappings). */
static int trace_resolve_base(pid_t pid) {
    char mpath[64];
    snprintf(mpath, sizeof mpath, "/proc/%d/maps", pid);
    FILE *f = fopen(mpath, "r");
    if (!f) return -1;
    char line[512];
    size_t namelen = strlen(trc.lib_name);
    while (fgets(line, sizeof line, f)) {
        char *p = strstr(line, trc.lib_name);
        if (!p) continue;
        /* ensure it's the path tail, not a random substring */
        if (p > line && p[-1] != '/' ) continue;
        if (p[namelen] != '\n' && p[namelen] != '\0' && p[namelen] != ' ') continue;
        unsigned long lo = strtoul(line, NULL, 16);
        /* remember the file path once for the byte check: the path starts
         * right after the whitespace that precedes the library name */
        char *pstart = p;
        while (pstart > line && pstart[-1] != ' ') pstart--;
        size_t plen = strlen(pstart);
        if (plen && pstart[plen - 1] == '\n') plen--;
        snprintf(trc.file_path, sizeof trc.file_path, "%.*s", (int)plen, pstart);
        if (!trc.base || lo < trc.base) trc.base = lo;
    }
    fclose(f);
    return trc.base ? 0 : -1;
}

/* runtime byte at addr vs the byte at the same RVA in the library file */
static int trace_byte_matches_file(pid_t pid, unsigned long addr) {
    errno = 0;
    long w = ptrace(PTRACE_PEEKDATA, pid, addr, 0);
    if (errno != 0) return -1;
    unsigned char runtime = (unsigned char)(w & 0xff);
    FILE *f = fopen(trc.file_path, "rb");
    if (!f) return -1;
    unsigned char filebyte = 0;
    int ok = 0;
    if (fseek(f, (long)trc.rva, SEEK_SET) == 0 && fread(&filebyte, 1, 1, f) == 1)
        ok = (runtime == filebyte);
    fclose(f);
    return ok;
}

static void trace_try_arm(pid_t pid) {
    if (!trc.requested || trc.done || trc.patched || trc.tracing || !trc.lib_seen)
        return;
    if (!trc.base && trace_resolve_base(pid) != 0) return;
    trc.patch_addr = trc.base + trc.rva;
    int m = trace_byte_matches_file(pid, trc.patch_addr);
    if (m != 1) {
        if (getenv("ADI_FREEZE_DEBUG_MAPS")) {
            char mp[64]; snprintf(mp, sizeof mp, "/proc/%d/maps", pid);
            FILE *f = fopen(mp, "r");
            char line[512];
            while (f && fgets(line, sizeof line, f))
                if (strstr(line, trc.lib_name))
                    fprintf(stderr, "[maps-dbg] %s", line);
            if (f) fclose(f);
            errno = 0;
            long db = ptrace(PTRACE_PEEKDATA, pid, trc.patch_addr, 0);
            fprintf(stderr, "[maps-dbg] base=0x%lx patch=0x%lx runtime_byte=%02x errno=%d\n",
                    trc.base, trc.patch_addr,
                    errno == 0 ? (unsigned)(db & 0xff) : 0u, errno);
        }
        /* not the load bias (transient/secondary mapping): keep scanning the
         * maps on later stops rather than patching a wrong address */
        trc.base = 0;
        return;
    }
    errno = 0;
    long w = ptrace(PTRACE_PEEKDATA, pid, trc.patch_addr, 0);
    if (errno != 0) return;
    trc.orig_byte = (unsigned char)(w & 0xff);
    long patched_w = (w & ~0xffL) | 0xcc;
    if (ptrace(PTRACE_POKEDATA, pid, trc.patch_addr, patched_w) < 0) return;
    trc.patched = 1;
    if (trc.out_path) trc.out = fopen(trc.out_path, "wb");
    if (trc.out) setvbuf(trc.out, NULL, _IOFBF, 1 << 20);
    if (trc.calls_path) {
        trc.calls = fopen(trc.calls_path, "w");
        if (trc.calls) setvbuf(trc.calls, NULL, _IOFBF, 1 << 20);
    }

    fprintf(stderr, "[trace] armed at %s+0x%lx = 0x%lx (orig byte 0x%02x, file-verified)\n",
            trc.lib_name, trc.rva, trc.patch_addr, trc.orig_byte);
    if (getenv("ADI_FREEZE_DEBUG_MAPS")) {
        /* dump every .so mapping once: the analyser needs module load biases
         * to map traced ips back to file offsets */
        char mp[64];
        snprintf(mp, sizeof mp, "/proc/%d/maps", pid);
        FILE *f = fopen(mp, "r");
        char line[512];
        while (f && fgets(line, sizeof line, f))
            if (strstr(line, ".so") || strstr(line, "adi_native"))
                fprintf(stderr, "[maps] %s", line);
        if (f) fclose(f);
    }
}


/* ---- options / counters -------------------------------------------------- */

struct dump_range { unsigned long long addr, size; char tag[192]; };
struct rdump { unsigned long long rec; unsigned long long addr, size; char tag[192]; };

static struct {
    long long epoch;          /* fixed realtime seconds; -1 = derive from host */
    const char *rng_hex;
    const char *urandom_hex;
    long long fixed_pid;
    long long fixed_tid;
    unsigned long long otp_buf;   /* known heap buffer address (no-ASLR rig) */
    int keep_vdso;
    int freeze_monotonic;
    int no_aslr;
    int quiet;
    int no_rng;               /* leave entropy sources live (bisection) */
    int no_clock;             /* leave time sources live (bisection) */
    int no_atrandom;          /* do not rewrite the AT_RANDOM auxv bytes */
    int no_getrandom;         /* leave getrandom(2) live (bisection) */
    int no_urandom;           /* leave /dev/urandom reads live (bisection) */
    int log_syscalls;         /* trace openat/open/read/getrandom ordering to stderr */
    int watch_state;          /* read watchpoints on a --trace-fd state read */
    int no_tsc_freeze;        /* leave rdtsc/rdtscp answers real (bisection) */
    unsigned long long tsc_base;  /* fake counter at the first rewrite; 0 = epoch<<21 */
    unsigned long long tsc_step;  /* fake counter advance per read; 0 = 4096 */
    struct dump_range dumps[16];
    int ndumps;               /* dumped when tracing stops (post-state) */
    struct dump_range sdumps[16];
    int nstartdumps;          /* dumped at the first trace stop (entry state) */
    struct rdump rdumps[256];
    int nrdumps;              /* dumped when record rec is written */
    struct dump_range mregions[16];
    int nmregions;            /* watched for cross-libc memory deltas */
    const char *mout_path;    /* delta log, written at trace stop */
    const char *maps_out;     /* /proc/<pid>/maps as of the traced entry */
} opt;

static struct {
    unsigned long long rng_hits, rng_bytes;
    unsigned long long urand_hits, urand_bytes;
    unsigned long long cgt_hits, gtd_hits, time_hits, pid_hits, tid_hits;
    unsigned long long epoch_value;
    int vdso_scan_ok;         /* auxv scan found the vDSO entry at all */
    int vdso_patched;         /* and the zero-write was verified */
} stat_;

/* ---- memory deltas across libc excursions -------------------------------- */
/* A stub replays the GP/XMM state at the call record, so any memory the libc
 * call wrote -- a struct stat, an iovec, a caller buffer -- would still hold
 * its pre-call contents in a VM that seeds only the entry state.  The libc
 * code itself is not lifted, so its stores have to cross the boundary as
 * data.  Instead of snapshotting the whole address space (tens of MiB) we
 * watch the regions the VM actually seeds, named with --trace-mem: at the
 * first libc record of an excursion take an image, at the first record back
 * in the engine diff 8-byte words and log (call, ret, addr, value) for the
 * ones that moved.
 * The 984-byte record layout is untouched: the log is a side file, one line
 * per changed word, "rec_call rec_ret addr value" in hex. */
#define MAX_MREGIONS 16
#define MAX_MLRANGES 16
static struct {
    unsigned long long addr, size;
} mregions[MAX_MREGIONS];
static int nmregions;
static unsigned long long *msnap[MAX_MREGIONS];
static unsigned long long mem_call_rec;
static int mem_prev_in_libc;
static struct {
    unsigned long long lo, hi;
} mlr[MAX_MLRANGES];
static int nmlr;

static void mem_resolve_libc(pid_t pid) {
    nmlr = 0;
    char mp[64];
    snprintf(mp, sizeof mp, "/proc/%d/maps", pid);
    FILE *f = fopen(mp, "r");
    if (!f) return;
    char line[512];
    while (fgets(line, sizeof line, f) && nmlr < MAX_MLRANGES) {
        unsigned long lo, hi;
        char perms[16];
        if (sscanf(line, "%lx-%lx %15s", &lo, &hi, perms) != 3) continue;
        if (!strchr(perms, 'x')) continue;
        if (!strstr(line, "libc.so")) continue;
        mlr[nmlr].lo = lo;
        mlr[nmlr].hi = hi;
        nmlr++;
    }
    fclose(f);
    fprintf(stderr, "[mem] libc executable ranges: %d\n", nmlr);
}

static int mem_in_libc(unsigned long long ip) {
    for (int i = 0; i < nmlr; i++)
        if (ip >= mlr[i].lo && ip < mlr[i].hi) return 1;
    return 0;
}

static void mem_snapshot(pid_t pid) {
    for (int i = 0; i < nmregions; i++) {
        unsigned long long words = (mregions[i].size + 7) / 8;
        if (!msnap[i]) msnap[i] = malloc(words * sizeof *msnap[i]);
        if (!msnap[i]) continue;
        char mp[64];
        snprintf(mp, sizeof mp, "/proc/%d/mem", pid);
        int fd = open(mp, O_RDONLY);
        if (fd < 0) continue;
        for (unsigned long long w = 0; w < words; w++) {
            unsigned long long va = mregions[i].addr + 8 * w;
            errno = 0;
            ssize_t got = pread(fd, &msnap[i][w], 8, (off_t)va);
            if (got != 8) msnap[i][w] = 0;
        }
        close(fd);
    }
}

static void mem_deltas(pid_t pid, unsigned long long rec_ret) {
    if (!opt.mout_path || !nmregions) return;
    FILE *f = fopen(opt.mout_path, "a");
    if (!f) return;
    char mp[64];
    snprintf(mp, sizeof mp, "/proc/%d/mem", pid);
    int fd = open(mp, O_RDONLY);
    if (fd < 0) { fclose(f); return; }
    unsigned long long changed = 0;
    for (int i = 0; i < nmregions; i++) {
        if (!msnap[i]) continue;
        unsigned long long words = (mregions[i].size + 7) / 8;
        for (unsigned long long w = 0; w < words; w++) {
            unsigned long long va = mregions[i].addr + 8 * w;
            unsigned long long cur = 0;
            errno = 0;
            if (pread(fd, &cur, 8, (off_t)va) != 8) continue;
            if (cur != msnap[i][w]) {
                fprintf(f, "%llu %llu %llx %016llx\n",
                        mem_call_rec, rec_ret, va, cur);
                changed++;
            }
        }
    }
    close(fd);
    fclose(f);
    if (changed)
        fprintf(stderr, "[mem] rec %llu -> %llu: %llu word(s)\n",
                mem_call_rec, rec_ret, changed);
}

static void mem_setup(pid_t pid) {
    if (!nmregions) return;
    if (!opt.mout_path) {
        fprintf(stderr, "[mem] --trace-mem needs --trace-mem-out, ignoring\n");
        nmregions = 0;
        return;
    }
    mem_resolve_libc(pid);
    if (!nmlr) {
        fprintf(stderr, "[mem] no executable libc mapping found\n");
        nmregions = 0;
    }
}

/* ---- deterministic byte stream ------------------------------------------- */

static uint8_t stream[64];
static size_t stream_len;
static uint8_t ustream[64];
static size_t ustream_len;

static void init_stream(const char *hex, uint8_t *buf, size_t *len) {
    size_t n = 0;
    if (hex) {
        for (const char *p = hex; p[0] && p[1]; p += 2) {
            int hi = p[0] <= '9' ? p[0] - '0' : (p[0] | 32) - 'a' + 10;
            int lo = p[1] <= '9' ? p[1] - '0' : (p[1] | 32) - 'a' + 10;
            if (n >= 64) break;
            buf[n++] = (uint8_t)((hi << 4) | lo);
        }
    }
    if (n == 0) { for (int i = 0; i < 32; i++) buf[i] = 0xA5; n = 32; }
    *len = n;
}

static void die(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    fprintf(stderr, "adi_freeze: ");
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
    exit(2);
}

/* ---- child memory helpers ------------------------------------------------- */

static int poke_bytes(pid_t pid, unsigned long addr, const uint8_t *src, unsigned long n) {
    unsigned long off = 0;
    while (off < n) {
        size_t chunk = n - off < 8 ? n - off : 8;
        errno = 0;
        long cur = 0;
        int have_cur = 0;
        if (chunk < 8) {
            cur = ptrace(PTRACE_PEEKDATA, pid, addr + off, 0);
            have_cur = (errno == 0);
            if (!have_cur) return -1;
        }
        uint8_t word[8];
        if (have_cur) memcpy(word, &cur, 8);
        memcpy(word, src + off, chunk);
        long w; memcpy(&w, word, 8);
        if (ptrace(PTRACE_POKEDATA, pid, addr + off, w) < 0) return -1;
        off += chunk;
    }
    return 0;
}

/* Fill [addr, addr+count) with the repeating pattern. */
static void fill_stream(pid_t pid, unsigned long addr, unsigned long count,
                        const uint8_t *pat, size_t plen,
                        unsigned long long *hits, unsigned long long *bytes) {
    if (!addr || !count) return;
    uint8_t tmp[512];
    unsigned long off = 0;
    while (off < count) {
        size_t chunk = count - off < sizeof tmp ? count - off : sizeof tmp;
        for (size_t i = 0; i < chunk; i++) tmp[i] = pat[(off + i) % plen];
        if (poke_bytes(pid, addr + off, tmp, chunk) < 0) return;
        off += chunk;
    }
    (*hits)++; *bytes += count;
}

static void read_child_string(pid_t pid, unsigned long addr, char *buf, size_t bufsz) {
    size_t i = 0;
    while (i + 1 < bufsz) {
        errno = 0;
        long w = ptrace(PTRACE_PEEKDATA, pid, addr + i, 0);
        if (errno != 0) break;
        uint8_t *p = (uint8_t *)&w;
        for (int k = 0; k < 8 && i + 1 < bufsz; k++) {
            buf[i++] = p[k];
            if (p[k] == 0) { buf[i] = 0; return; }
        }
    }
    buf[i] = 0;
}

/* ---- watched-file I/O and memory scans (state-format work) ---------------- */
/*
 * --trace-fd=SUFFIX:DIR  dumps every read/write buffer on fds opened from a
 *                        path ending in SUFFIX (the engine's adi.pb, for
 *                        example) to DIR/io-NN-read.bin / io-NN-write.bin.
 * --scan-mem=HEX:TAG     scans readable mappings at the trigger point for a
 *                        byte pattern and dumps a window around each hit.
 * --scan-at-path=NAME    triggers the scan when the harness opens NAME
 *                        (e.g. adi-state-before-otp.bin, i.e. after the
 *                        engine has parsed the state).
 * --scan-dir=DIR         where the scan windows are written.
 * A scan is also taken at exit_group, before the address space disappears.
 */
static struct {
    const char *suffix;
    const char *dir;
    int fds[16];
    int nfds;
    int seq;
} iow;

static struct {
    unsigned char pat[64];
    int len;
    char tag[32];
} mscan[4];
static int nmscan;
static const char *scan_at_path;
static const char *scan_dir;

static int path_ends_with(const char *path, const char *suffix) {
    size_t a = strlen(path), b = strlen(suffix);
    return a >= b && strcmp(path + a - b, suffix) == 0;
}

static int iow_watched(long fd) {
    for (int i = 0; i < iow.nfds; i++)
        if (iow.fds[i] == fd) return 1;
    return 0;
}

static void iow_add_fd(long fd) {
    if (iow.nfds < (int)(sizeof iow.fds / sizeof *iow.fds)) iow.fds[iow.nfds++] = (int)fd;
}

static void iow_del_fd(long fd) {
    for (int i = 0; i < iow.nfds; i++)
        if (iow.fds[i] == fd) { iow.fds[i] = iow.fds[--iow.nfds]; return; }
}

static void child_mem_read(pid_t pid, unsigned long long addr, unsigned char *out, size_t len) {
    size_t off = 0;
    while (off < len) {
        errno = 0;
        long w = ptrace(PTRACE_PEEKDATA, pid, (void *)(unsigned long)(addr + off), 0);
        if (errno != 0) { memset(out + off, 0, len - off); return; }
        size_t n = len - off < 8 ? len - off : 8;
        memcpy(out + off, &w, n);
        off += n;
    }
}

static void iow_dump(pid_t pid, const char *op, unsigned long long addr, size_t len) {
    if (!iow.dir || len == 0 || len > (1u << 20)) return;
    unsigned char *buf = malloc(len);
    if (!buf) return;
    child_mem_read(pid, addr, buf, len);
    char path[512];
    snprintf(path, sizeof path, "%s/io-%02d-%s.bin", iow.dir, iow.seq++, op);
    FILE *f = fopen(path, "wb");
    if (f) { fwrite(buf, 1, len, f); fclose(f); }
    fprintf(stderr, "[io] %s %s %llx..%llx (%zu bytes)\n", op, path,
            addr, addr + len, len);
    free(buf);
}

/* ---- read watchpoints on the loaded state buffer -------------------------- */
/*
 * --watch-state arms DR0..DR3 with 8-byte read/write watchpoints on a state
 * file buffer right after the engine reads it: header, blob start, and the
 * first/last 8-byte window of the fixed 580-byte tail. Every distinct
 * (slot, rip) pair is logged once, with the 16 bytes before rip, so the
 * consuming instruction can be decoded offline. This locates the identity
 * check and the tail decryption without a multi-million-record step trace.
 */
static int sw_on;
static int sw_fixed_mode;         /* slots are --watch-fixed addresses */
static int sw_epoch;              /* bumped on every arm: threads re-arm lazily */
static unsigned long sw_addr[4];
static const char *sw_name[4] = { "header", "blob", "tail-first", "tail-last" };
static unsigned long sw_seen[4][64];
static int sw_nseen[4];
static unsigned long long sw_hits;

/* the watchpoint registers are per-thread: every traced thread must be
 * re-armed for itself after the buffer address changes (the OTP engine runs
 * on libdispatch workers, so one arm in the reader is not enough). */
static void state_watch_arm_thread(pid_t pid) {
    for (int i = 0; i < 4; i++)
        ptrace(PTRACE_POKEUSER, pid,
               (void *)offsetof(struct user, u_debugreg[i]), (void *)sw_addr[i]);
    ptrace(PTRACE_POKEUSER, pid,
           (void *)offsetof(struct user, u_debugreg[6]), 0);
    unsigned long dr7 = 0xFUL | (0xFUL << 16) | (0xFUL << 20) |
                        (0xFUL << 24) | (0xFUL << 28);
    if (ptrace(PTRACE_POKEUSER, pid,
               (void *)offsetof(struct user, u_debugreg[7]), (void *)dr7) < 0)
        fprintf(stderr, "[sw] thread arm failed tid=%d\n", pid);
}

/* --watch-state-offsets=O0,O1,O2,O3: 8-byte windows at these byte offsets
 * from the start of the fixed 580-byte tail (default 0,8,572). */
static unsigned long sw_off[4] = { 0, 8, 572, 0 };
static int sw_noff = 3;
static int sw_off_given;

static void state_watch_arm(pid_t pid, unsigned long buf) {
    unsigned char hdr[8];
    child_mem_read(pid, buf, hdr, sizeof hdr);
    unsigned n = ((unsigned)hdr[4] << 24) | ((unsigned)hdr[5] << 16) |
                 ((unsigned)hdr[6] << 8) | hdr[7];
    unsigned long tail = buf + 8 + n;
    int tail_slots = sw_off_given ? 4 : 2;
    int first_tail = 4 - tail_slots;
    if (!sw_off_given) {
        sw_addr[0] = buf & ~7UL;
        sw_addr[1] = (buf + 8) & ~7UL;
    }
    for (int i = first_tail; i < 4; i++) {
        int k = i - first_tail;
        unsigned long off = sw_off[k < sw_noff ? k : sw_noff - 1];
        sw_addr[i] = (tail + off) & ~7UL;
    }
    sw_epoch++;
    state_watch_arm_thread(pid);
    sw_on = 1;
    sw_fixed_mode = 0;
    fprintf(stderr, "[sw] armed buf=%lx n=%u tail=%lx slots %lx %lx %lx %lx offsets",
            buf, n, tail, sw_addr[0], sw_addr[1], sw_addr[2], sw_addr[3]);
    for (int k = 0; k < (sw_off_given ? 4 : 2); k++)
        fprintf(stderr, " %lu", sw_off[k]);
    fprintf(stderr, "\n");
}

/* --watch-fixed=HEX[,HEX,HEX,HEX]: arm up to four arbitrary 8-byte windows,
 * used for stack copies discovered by --scan-mem. Armed when the harness opens
 * --scan-at-path (immediately before the OTP call), so the window is quiet. */
static unsigned long sw_fixed[4];
static int sw_nfixed;
static const char *sw_scan_tag;   /* --watch-scan-tag: arm at this scan hit */
static unsigned long sw_scan_off; /* byte offset added to the hit */

static void state_watch_arm_scan(pid_t pid, unsigned long va) {
    unsigned long start = (va + sw_scan_off) & ~7UL;
    sw_addr[0] = start;
    sw_addr[1] = start + 8;
    sw_addr[2] = start + 16;
    sw_addr[3] = start + 24;
    sw_epoch++;
    state_watch_arm_thread(pid);
    sw_on = 1;
    sw_fixed_mode = 2;
    fprintf(stderr, "[sw] scan-arm va=%lx off=%lu slots %lx %lx %lx %lx\n",
            va, sw_scan_off, sw_addr[0], sw_addr[1], sw_addr[2], sw_addr[3]);
}

static void state_watch_arm_fixed(pid_t pid) {
    for (int i = 0; i < 4; i++)
        sw_addr[i] = i < sw_nfixed ? (sw_fixed[i] & ~7UL) : (sw_fixed[0] & ~7UL);
    sw_epoch++;
    state_watch_arm_thread(pid);
    sw_on = 1;
    sw_fixed_mode = 1;
    fprintf(stderr, "[sw] fixed armed slots %lx %lx %lx %lx\n",
            sw_addr[0], sw_addr[1], sw_addr[2], sw_addr[3]);
}

static void state_watch_hit(pid_t pid) {
    if (!sw_on) return;
    errno = 0;
    long dr6 = ptrace(PTRACE_PEEKUSER, pid,
                      (void *)offsetof(struct user, u_debugreg[6]), 0);
    if (errno != 0 || !(dr6 & 0xF)) return;
    struct user_regs_struct r;
    if (ptrace(PTRACE_GETREGS, pid, 0, &r) == 0) {
        unsigned char back[16];
        child_mem_read(pid, (unsigned long long)r.rip - sizeof back, back, sizeof back);
        for (int i = 0; i < 4; i++) {
            if (!(dr6 & (1L << i))) continue;
            sw_hits++;
            int dup = 0;
            for (int k = 0; k < sw_nseen[i]; k++)
                if (sw_seen[i][k] == (unsigned long)r.rip) { dup = 1; break; }
            if (!dup && sw_nseen[i] < 64) {
                sw_seen[i][sw_nseen[i]++] = (unsigned long)r.rip;
                fprintf(stderr,
                        "[sw] hit tid=%d slot=%d(%s%c%d) addr=%lx rip=%lx back=",
                        pid, i,
                        sw_fixed_mode == 2 ? "scan" : sw_fixed_mode ? "fixed" : sw_name[i],
                        sw_fixed_mode ? '#' : ' ', i, sw_addr[i], (unsigned long)r.rip);
                for (size_t b = 0; b < sizeof back; b++) fprintf(stderr, "%02x", back[b]);
                fprintf(stderr,
                        " rax=%llx rbx=%llx rcx=%llx rdx=%llx rsi=%llx rdi=%llx "
                        "rbp=%llx rsp=%llx r8=%llx r9=%llx r10=%llx r11=%llx "
                        "r12=%llx r13=%llx r14=%llx r15=%llx\n",
                        (unsigned long long)r.rax, (unsigned long long)r.rbx,
                        (unsigned long long)r.rcx, (unsigned long long)r.rdx,
                        (unsigned long long)r.rsi, (unsigned long long)r.rdi,
                        (unsigned long long)r.rbp, (unsigned long long)r.rsp,
                        (unsigned long long)r.r8, (unsigned long long)r.r9,
                        (unsigned long long)r.r10, (unsigned long long)r.r11,
                        (unsigned long long)r.r12, (unsigned long long)r.r13,
                        (unsigned long long)r.r14, (unsigned long long)r.r15);
            }
        }
    }
    ptrace(PTRACE_POKEUSER, pid,
           (void *)offsetof(struct user, u_debugreg[6]), 0);   /* clear sticky */
}

static void scan_memory(pid_t pid, const char *why) {
    if (!nmscan) return;
    char mp[64];
    snprintf(mp, sizeof mp, "/proc/%d/maps", pid);
    FILE *mf = fopen(mp, "r");
    if (!mf) return;
    char memp[64];
    snprintf(memp, sizeof memp, "/proc/%d/mem", pid);
    int mfd = open(memp, O_RDONLY);
    if (mfd < 0) { fclose(mf); return; }
    char line[512];
    unsigned char *chunk = malloc((1u << 16) + 64);
    if (!chunk) { close(mfd); fclose(mf); return; }
    unsigned long long scanned = 0;
    fprintf(stderr, "[scan] trigger=%s pid=%d patterns=%d\n", why, pid, nmscan);
    while (fgets(line, sizeof line, mf)) {
        unsigned long lo, hi;
        char perms[16], rest[256] = "";
        if (sscanf(line, "%lx-%lx %15s %*s %*s %*s %255[^\n]", &lo, &hi, perms, rest) < 3)
            continue;
        /* decrypted state lives in writable anonymous memory: scanning the
         * file-backed library/oat mappings as well made the first version take
         * minutes on a Bionic address space, so restrict to rw and skip DEX/
         * native images explicitly. */
        if (perms[0] != 'r' || perms[1] != 'w') continue;
        if (strstr(rest, ".so") || strstr(rest, ".dex") || strstr(rest, ".oat") ||
            strstr(rest, ".art") || strstr(rest, ".apk"))
            continue;
        unsigned long long size = hi - lo;
        if (size == 0 || size > (64ull << 20)) continue;
        if (scanned + size > (256ull << 20)) break;
        scanned += size;
        if (getenv("ADI_SCAN_DEBUG"))
            fprintf(stderr, "[scan] map %lx-%lx (%llu) %s\n", lo, hi, size, rest);
        for (int s = 0; s < nmscan; s++) {
            int hits = 0;
            unsigned long long off = 0;
            while (off < size && hits < 8) {
                size_t want = sizeof(unsigned char) * (1u << 16);
                if (size - off < want) want = (size_t)(size - off);
                errno = 0;
                ssize_t got = pread(mfd, chunk, want, (off_t)(lo + off));
                if (got <= 0) break;
                unsigned char *p = chunk, *end = chunk + got;
                while (p + mscan[s].len <= end && hits < 8) {
                    unsigned char *m = memmem(p, (size_t)(end - p),
                                              mscan[s].pat, (size_t)mscan[s].len);
                    if (!m) break;
                    unsigned long long va = lo + off + (unsigned long long)(m - chunk);
                    unsigned long long ws = va > 256 ? va - 256 : 0;
                    unsigned long long we = va + 256;
                    if (we > hi) we = hi;
                    char path[512];
                    snprintf(path, sizeof path, "%s/scan-%s-%d-%d.bin",
                             scan_dir ? scan_dir : ".", mscan[s].tag, pid, hits);
                    FILE *f = fopen(path, "wb");
                    if (f) {
                        unsigned long long wl = we - ws;
                        unsigned char *w = malloc(wl ? wl : 1);
                        if (w) {
                            child_mem_read(pid, ws, w, (size_t)wl);
                            fwrite(w, 1, (size_t)wl, f);
                            free(w);
                        }
                        fclose(f);
                    }
                    fprintf(stderr, "[scan] %s hit at %llx (%s)\n",
                            mscan[s].tag, va, path);
                    if (sw_scan_tag && !strcmp(mscan[s].tag, sw_scan_tag))
                        state_watch_arm_scan(pid, (unsigned long)va);
                    hits++;
                    p = m + 1;
                }
                if ((size_t)got < want) break;
                if (off + (unsigned long long)got >= size) break;
                off += (size_t)got - (mscan[s].len > 1 ? (size_t)mscan[s].len - 1 : 0);
            }
        }
    }
    free(chunk);
    close(mfd);
    fclose(mf);
}

/* ---- per-process state ----------------------------------------------------- */

struct pstate {
    pid_t pid;
    int in_syscall;          /* 0 = last stop was entry, 1 = exit pending */
    int open_is_urandom;     /* flagged at open entry, consumed at open exit */
    int open_watch;          /* flagged at open entry: path matched --trace-fd */
    int exec_seen;
    long close_fd;           /* fd seen at close/dup entry */
    int tracing;             /* this process is being single-stepped (trace mode) */
    unsigned long prev_ip;   /* last single-stepped instruction (TSC check) */
    int prev_valid;
    /* --trace-fd: pending read of a watched fd */
    int watch_read_pending;
    int watch_read_fd;
    unsigned long long watch_read_buf;
    int call_depth;          /* --call-log nesting for this thread */
    int sw_epoch_seen;       /* which state-watch generation this thread has */
};
static struct pstate procs[MAX_PID_SLOTS];
static int procs_n;

static struct pstate *pstate_of(pid_t pid) {
    for (int i = 0; i < procs_n; i++) if (procs[i].pid == pid) return &procs[i];
    if (procs_n == MAX_PID_SLOTS) return NULL;
    memset(&procs[procs_n], 0, sizeof procs[procs_n]);
    procs[procs_n].pid = pid;
    return &procs[procs_n++];
}
static void pstate_drop(pid_t pid) {
    int w = 0;
    for (int i = 0; i < procs_n; i++) if (procs[i].pid != pid) procs[w++] = procs[i];
    procs_n = w;
}

/* arm this thread if a newer state buffer was read since its last stop */
static void state_watch_sync(pid_t pid) {
    struct pstate *ps = pstate_of(pid);
    if (!ps || !sw_on || ps->sw_epoch_seen == sw_epoch) return;
    state_watch_arm_thread(pid);
    ps->sw_epoch_seen = sw_epoch;
}

/* compact call stream: C <depth> <site> <target> <next-ip> / R <depth> <ret-ip> <next-ip>.
 * The instruction at prev_ip has just executed; a direct call is decoded from
 * the file-verified bytes, an indirect call's target is the new rip. */
static void trace_calllog(pid_t tid, struct pstate *ps, unsigned long long rip) {
    if (!trc.calls || !ps->prev_valid) return;
    errno = 0;
    long iw = ptrace(PTRACE_PEEKDATA, tid, ps->prev_ip, 0);
    if (errno != 0) return;
    unsigned char b0 = (unsigned char)(iw & 0xff);
    unsigned char b1 = (unsigned char)((iw >> 8) & 0xff);
    if (b0 == 0xe8) {
        long long rel = (long long)(int32_t)(((unsigned long long)iw >> 8) & 0xffffffffu);
        fprintf(trc.calls, "C %d %llx %llx %llx\n", ps->call_depth++,
                (unsigned long long)ps->prev_ip,
                (unsigned long long)((long long)ps->prev_ip + 5 + rel), rip);
    } else if (b0 == 0xff && (((b1 >> 3) & 7) == 2)) {
        fprintf(trc.calls, "C %d %llx %llx %llx\n", ps->call_depth++,
                (unsigned long long)ps->prev_ip, rip, rip);
    } else if (b0 == 0xc3 || b0 == 0xc2) {
        if (ps->call_depth > 0) ps->call_depth--;
        fprintf(trc.calls, "R %d %llx %llx\n", ps->call_depth,
                (unsigned long long)ps->prev_ip, rip);
    }
}

/* stop tracing every thread: the harness capture of mid.bin/otp.bin has
 * started, so the outputs are final. done also prevents trace_try_arm from
 * re-arming the int3 and re-opening (truncating!) the trace file on the
 * next syscall boundary. */
static void dump_ranges(pid_t pid, struct dump_range *ds, int n) {
    for (int i = 0; i < n; i++) {
        struct dump_range *d = &ds[i];
        FILE *f = fopen(d->tag, "wb");
        if (!f) { fprintf(stderr, "[dump] cannot open %s\n", d->tag); continue; }
        for (unsigned long long off = 0; off < d->size; off += 8) {
            errno = 0;
            long w = ptrace(PTRACE_PEEKDATA, pid,
                            (void *)(unsigned long)(d->addr + off), 0);
            unsigned long long v = errno == 0 ? (unsigned long long)w : 0;
            if (off + 8 > d->size) {
                /* partial tail: read bytes individually */
                unsigned long long have = d->size - off;
                fwrite(&v, 1, (size_t)have, f);
            } else {
                fwrite(&v, 1, 8, f);
            }
        }
        fclose(f);
        fprintf(stderr, "[dump] %s: %llx..%llx (%llu bytes)\n", d->tag,
                d->addr, d->addr + d->size, d->size);
    }
}

static int reg_index(const char *name) {
    static const char *names[16] = { "rax", "rbx", "rcx", "rdx", "rsi", "rdi",
                                     "rbp", "rsp", "r8", "r9", "r10", "r11",
                                     "r12", "r13", "r14", "r15" };
    for (int i = 0; i < 16; i++) if (!strcmp(name, names[i])) return i;
    return -1;
}

static unsigned long long reg_get(const struct user_regs_struct *r, int i) {
    switch (i) {
    case 0: return r->rax;   case 1: return r->rbx;
    case 2: return r->rcx;   case 3: return r->rdx;
    case 4: return r->rsi;   case 5: return r->rdi;
    case 6: return r->rbp;   case 7: return r->rsp;
    case 8: return r->r8;    case 9: return r->r9;
    case 10: return r->r10;  case 11: return r->r11;
    case 12: return r->r12;  case 13: return r->r13;
    case 14: return r->r14;  case 15: return r->r15;
    default: return 0;
    }
}

static void dump_reg_dumps(pid_t pid, const struct user_regs_struct *r,
                           const struct reg_dump *ds, int n, const char *when) {
    for (int i = 0; i < n; i++) {
        unsigned long long a = reg_get(r, ds[i].reg) + (unsigned long long)ds[i].off;
        if (ds[i].deref) {
            unsigned long long ptr = 0;
            child_mem_read(pid, a, (unsigned char *)&ptr, sizeof ptr);
            a = ptr;
        }
        size_t len = (size_t)ds[i].size;
        unsigned char *buf = malloc(len ? len : 1);
        if (!buf) continue;
        memset(buf, 0, len);
        child_mem_read(pid, a, buf, len);
        FILE *f = fopen(ds[i].tag, "wb");
        if (f) { fwrite(buf, 1, len, f); fclose(f); }
        fprintf(stderr, "[dump] %s %s: %llx..%llx (%zu bytes)\n",
                when, ds[i].tag, a, a + len, len);
        free(buf);
    }
}

static void trace_stop_all(pid_t pid) {
    if (!trc.tracing) return;
    trc.tracing = 0;
    trc.done = 1;
    for (int i = 0; i < procs_n; i++) procs[i].tracing = 0;
    wp_disarm(pid);
    /* post-state memory dumps (diagnostics; VM seeds use --dump-start) */
    dump_ranges(pid, opt.dumps, opt.ndumps);
    if (trc.out) fflush(trc.out);
    fprintf(stderr, "[trace] stopped all threads after %llu records\n", trc.steps);
}

/* /dev/urandom fd tracking per process */
#define MAX_URANDOM_FDS 128
static struct { pid_t pid; int fd; } urandom_fds[MAX_URANDOM_FDS];
static int urandom_fds_n;

static void mark_urandom_fd(pid_t pid, int fd) {
    for (int i = 0; i < urandom_fds_n; i++)
        if (urandom_fds[i].pid == pid && urandom_fds[i].fd == fd) return;
    if (urandom_fds_n == MAX_URANDOM_FDS) return;
    urandom_fds[urandom_fds_n].pid = pid;
    urandom_fds[urandom_fds_n].fd = fd;
    urandom_fds_n++;
}
static int is_urandom_fd(pid_t pid, long fd) {
    for (int i = 0; i < urandom_fds_n; i++)
        if (urandom_fds[i].pid == pid && urandom_fds[i].fd == fd) return 1;
    return 0;
}
static void forget_urandom_fd(pid_t pid, int fd) {
    int w = 0;
    for (int i = 0; i < urandom_fds_n; i++) {
        if (urandom_fds[i].pid == pid && urandom_fds[i].fd == fd) continue;
        urandom_fds[w++] = urandom_fds[i];
    }
    urandom_fds_n = w;
}
static void forget_pid_fds(pid_t pid) {
    int w = 0;
    for (int i = 0; i < urandom_fds_n; i++)
        if (urandom_fds[i].pid != pid) urandom_fds[w++] = urandom_fds[i];
    urandom_fds_n = w;
}

/* ---- vDSO kill + AT_RANDOM freeze in the child auxv ------------------------ */

static void patch_auxv(pid_t pid) {
    struct user_regs_struct r;
    if (ptrace(PTRACE_GETREGS, pid, 0, &r) < 0) return;
    errno = 0;
    long aw = ptrace(PTRACE_PEEKDATA, pid, (unsigned long)r.rsp, 0);
    if (errno != 0) return;
    unsigned long argc = (unsigned long)aw;
    /* skip argc, argv pointers and the argv NULL terminator */
    unsigned long a = (unsigned long)r.rsp + 8 * (argc + 2);
    /* skip envp pointers up to and including the envp NULL (an empty envp
     * makes this the same slot; both layouts then reach the auxv) */
    for (unsigned long k = 0; k < 4096; k++, a += 8) {
        errno = 0;
        long v = ptrace(PTRACE_PEEKDATA, pid, a, 0);
        if (errno != 0) return;
        if (v == 0) { a += 8; break; }
    }
    /* a now points at the first auxv a_type */
    for (unsigned long j = 0; j < 64; j++, a += 16) {
        errno = 0;
        long typ = ptrace(PTRACE_PEEKDATA, pid, a, 0);
        if (errno != 0) return;
        if ((unsigned long)typ == AT_SYSINFO_EHDR) {
            if (!opt.keep_vdso) {
                ptrace(PTRACE_POKEDATA, pid, a + 8, 0);
                /* verify the write took: a zero-hit freeze is not a
                 * controlled source, and neither is an unverified patch */
                errno = 0;
                long back = ptrace(PTRACE_PEEKDATA, pid, a + 8, 0);
                stat_.vdso_patched = (errno == 0 && back == 0);
                stat_.vdso_scan_ok = 1;
            } else {
                stat_.vdso_scan_ok = 1;
            }
        } else if ((unsigned long)typ == AT_RANDOM && !opt.no_rng && !opt.no_atrandom) {
            long ptr = ptrace(PTRACE_PEEKDATA, pid, a + 8, 0);
            if (errno == 0 && ptr)
                fill_stream(pid, (unsigned long)ptr, 16,
                            stream, stream_len, &stat_.rng_hits, &stat_.rng_bytes);
        }
        if ((unsigned long)typ == 0) return;   /* AT_NULL */
    }
}

/* ---- syscall-exit rewriting ------------------------------------------------ */

static void freeze_clock_answer(pid_t pid, unsigned long addr) {
    long wsec = (long)opt.epoch;
    long wnsec = 0;
    ptrace(PTRACE_POKEDATA, pid, addr, wsec);
    ptrace(PTRACE_POKEDATA, pid, addr + 8, wnsec);
}

static void log_syscall(pid_t pid, const char *dir, long nr, struct user_regs_struct *r) {
    if (nr == SYS_read || nr == SYS_write || nr == SYS_pwrite64) {
        fprintf(stderr, "%s pid=%d nr=%ld fd=%lld buf=%llx len=%llu ret=%lld\n",
                dir, pid, nr, (long long)r->rdi,
                (unsigned long long)r->rsi, (unsigned long long)r->rdx,
                (long long)r->rax);
        return;
    }
    if (nr == SYS_lseek) {
        fprintf(stderr, "%s pid=%d lseek fd=%lld off=%lld whence=%lld ret=%lld\n",
                dir, pid, (long long)r->rdi, (long long)r->rsi,
                (long long)r->rdx, (long long)r->rax);
        return;
    }
    if (nr == SYS_ftruncate) {
        fprintf(stderr, "%s pid=%d ftruncate fd=%lld len=%lld ret=%lld\n",
                dir, pid, (long long)r->rdi, (long long)r->rsi, (long long)r->rax);
        return;
    }
    if (nr == SYS_rename || nr == SYS_unlink || nr == SYS_unlinkat) {
        unsigned long pa = r->rdi;
        if (nr == SYS_unlinkat) pa = (unsigned long)r->rsi;
        char tmp[96];
        read_child_string(pid, pa, tmp, sizeof tmp);
        fprintf(stderr, "%s pid=%d nr=%ld %s ret=%lld\n", dir, pid, nr, tmp, (long long)r->rax);
        return;
    }
    long interesting[13] = { SYS_read, SYS_open, SYS_openat, SYS_close,
                             SYS_dup, SYS_dup2, SYS_dup3, SYS_getrandom,
                             SYS_clock_gettime, SYS_gettimeofday, SYS_time,
                             SYS_getpid, SYS_gettid };
    for (unsigned i = 0; i < sizeof interesting / sizeof *interesting; i++) {
        if (interesting[i] == nr) {
            char path[96] = "";
            if (nr == SYS_read || nr == SYS_openat || nr == SYS_open ||
                nr == SYS_close || nr == SYS_dup || nr == SYS_dup2 || nr == SYS_dup3)
                snprintf(path, sizeof path, "fd=%lld ", (long long)r->rdi);
            if (nr == SYS_openat || nr == SYS_open) {
                unsigned long pa = nr == SYS_openat ? (unsigned long)r->rsi : (unsigned long)r->rdi;
                char tmp[80];
                read_child_string(pid, pa, tmp, sizeof tmp);
                strncat(path, tmp, sizeof path - strlen(path) - 1);
            }
            fprintf(stderr, "%s pid=%d nr=%ld %sret=%llx\n", dir, pid, nr, path,
                    (unsigned long long)r->rax);
            return;
        }
    }
}

static void handle_syscall_exit(pid_t pid, struct user_regs_struct *r, long nr) {
    switch (nr) {
    case SYS_getrandom:
        if (!opt.no_rng && !opt.no_getrandom)
            fill_stream(pid, (unsigned long)r->rdi, (unsigned long)r->rax,
                        stream, stream_len, &stat_.rng_hits, &stat_.rng_bytes);
        break;
    case SYS_read:
    case SYS_pread64: {
        struct pstate *ps = pstate_of(pid);
        if (ps && ps->watch_read_pending && ps->watch_read_fd == (int)r->rdi &&
            (long)r->rax > 0) {
            iow_dump(pid, "read", ps->watch_read_buf, (size_t)r->rax);
            if (opt.watch_state)
                state_watch_arm(pid, (unsigned long)ps->watch_read_buf);
        }
        if (ps) ps->watch_read_pending = 0;
        if (is_urandom_fd(pid, (long)r->rdi) && !opt.no_rng && !opt.no_urandom)
            fill_stream(pid, (unsigned long)r->rsi, (unsigned long)r->rax,
                        ustream, ustream_len, &stat_.urand_hits, &stat_.urand_bytes);
        break;
    }
    case SYS_open:
    case SYS_openat: {
        struct pstate *ps = pstate_of(pid);
        if (ps && ps->open_is_urandom && r->rax >= 0 && r->rax < 0x7fffffff)
            mark_urandom_fd(pid, (int)r->rax);
        if (ps && ps->open_watch && r->rax >= 0 && r->rax < 0x7fffffff)
            iow_add_fd((long)r->rax);
        if (ps) { ps->open_is_urandom = 0; ps->open_watch = 0; }
        break;
    }
    case SYS_close: {
        /* fd lifecycle tracking: a closed urandom fd must leave the table or
         * its number will be silently reused by the next open and our fill
         * would poison an unrelated read (this corrupted adi.pb reads). */
        struct pstate *ps = pstate_of(pid);
        if (ps && ps->close_fd >= 0 && r->rax == 0) {
            forget_urandom_fd(pid, (int)ps->close_fd);
            iow_del_fd(ps->close_fd);
        }
        break;
    }
    case SYS_dup:
    case SYS_dup2:
    case SYS_dup3: {
        /* success: the return value is the NEW fd. If the old fd is a tracked
         * urandom fd, the copy serves the same file and must be tracked too.
         * dup2/dup3 additionally destroy whatever newfd pointed at. */
        struct pstate *ps = pstate_of(pid);
        long oldfd = ps ? ps->close_fd : -1;
        if (ps && r->rax >= 0 && r->rax < 0x7fffffff &&
            oldfd >= 0 && is_urandom_fd(pid, oldfd))
            mark_urandom_fd(pid, (int)r->rax);
        break;
    }
    case SYS_clock_gettime: {
        int clk = (int)r->rdi;
        int relevant = (clk == CLOCK_REALTIME) || opt.freeze_monotonic;
        if (relevant && !opt.no_clock) {
            if (r->rax == 0 && r->rsi) freeze_clock_answer(pid, (unsigned long)r->rsi);
            stat_.cgt_hits++;
        }
        break;
    }
    case SYS_gettimeofday:
        if (!opt.no_clock && r->rax == 0 && r->rdi)
            freeze_clock_answer(pid, (unsigned long)r->rdi);
        if (!opt.no_clock) stat_.gtd_hits++;
        break;
    case SYS_time:
        if (!opt.no_clock) {
            if (r->rax != (unsigned long)-1) {
                struct user_regs_struct r2 = *r;
                r2.rax = (unsigned long long)opt.epoch;
                ptrace(PTRACE_SETREGS, pid, 0, &r2);
                if (r->rdi) {
                    long wsec = (long)opt.epoch;
                    ptrace(PTRACE_POKEDATA, pid, (unsigned long)r->rdi, wsec);
                }
            }
            stat_.time_hits++;
        }
        break;
    case SYS_getpid:
        if (opt.fixed_pid > 0) {
            struct user_regs_struct r2 = *r;
            r2.rax = (unsigned long long)opt.fixed_pid;
            ptrace(PTRACE_SETREGS, pid, 0, &r2);
        }
        stat_.pid_hits++;
        break;
    case SYS_gettid:
        if (opt.fixed_tid > 0) {
            struct user_regs_struct r2 = *r;
            r2.rax = (unsigned long long)opt.fixed_tid;
            ptrace(PTRACE_SETREGS, pid, 0, &r2);
        }
        stat_.tid_hits++;
        break;
    default:
        break;
    }
}

static void handle_syscall_entry(pid_t pid, struct user_regs_struct *r) {
    struct pstate *ps = pstate_of(pid);
    if (!ps) return;
    long nr = (long)r->orig_rax;

    if (nr == SYS_exit_group) scan_memory(pid, "exit_group");

    if (iow.suffix && (nr == SYS_write || nr == SYS_pwrite64)) {
        long fd = (long)r->rdi;
        if (iow_watched(fd))
            iow_dump(pid, nr == SYS_write ? "write" : "pwrite",
                     (unsigned long long)r->rsi, (size_t)r->rdx);
    }
    if (nr == SYS_read && iow_watched((long)r->rdi)) {
        ps->watch_read_pending = 1;
        ps->watch_read_fd = (int)r->rdi;
        ps->watch_read_buf = (unsigned long long)r->rsi;
    }

        if (nr == SYS_open || nr == SYS_openat) {
        unsigned long patharg = nr == SYS_open ? (unsigned long)r->rdi : (unsigned long)r->rsi;
        char path[128];
        read_child_string(pid, patharg, path, sizeof path);
        ps->open_is_urandom = !strcmp(path, "/dev/urandom") || !strcmp(path, "/dev/random");
        ps->open_watch = iow.suffix && path_ends_with(path, iow.suffix);
        if (scan_at_path) {
            const char *base = strrchr(path, '/');
            base = base ? base + 1 : path;
            if (!strcmp(base, scan_at_path)) {
                scan_memory(pid, base);
                if (sw_nfixed) state_watch_arm_fixed(pid);
            }
        }
        if (trc.requested && !trc.lib_seen && !trc.patched) {
            const char *base = strrchr(path, '/');
            if (base && !strcmp(base + 1, trc.lib_name)) trc.lib_seen = 1;
        }
        /* the harness writes the final MID/OTP captures right after pOTP
         * returns: that is the reliable end of the async computation */
        if (trc.tracing) {
            const char *base = strrchr(path, '/');
            base = base ? base + 1 : path;
            if (!strcmp(base, "mid.bin") || !strcmp(base, "otp.bin")) {
                if (wp_payload && getenv("ADI_FREEZE_DEBUG_WP")) {
                    errno = 0;
                    long optr = ptrace(PTRACE_PEEKDATA, pid, wp_ptrvar, 0);
                    fprintf(stderr, "[wp] capture: ptrvar=%lx optr=%lx watched=%lx\n",
                            wp_ptrvar, errno == 0 ? (unsigned long)optr : 0ul,
                            wp_payload);
                    for (int k = -2; k < 4; k++) {
                        errno = 0;
                        long w = ptrace(PTRACE_PEEKDATA, pid,
                                        wp_payload + 8 * k, 0);
                        fprintf(stderr, "[wp] buf%+d = %016lx%s\n", 8 * k,
                                errno == 0 ? (unsigned long)w : 0ul,
                                errno ? " (unmapped)" : "");
                    }
                }
                trace_stop_all(pid);
            }
        }
        ps->close_fd = -1;
    } else {
        ps->open_is_urandom = 0;
        /* remember the fd argument of close/dup for the exit pass */
        ps->close_fd = (nr == SYS_close || nr == SYS_dup ||
                        nr == SYS_dup2 || nr == SYS_dup3) ? (long)r->rdi : -1;
    }
}

static void report(void) {
    const char *vdso_s = opt.keep_vdso ? "kept"
                       : stat_.vdso_scan_ok ? (stat_.vdso_patched ? "patched" : "patch-failed")
                       : "auxv-scan-failed";
    fprintf(stderr,
        "{\"adi_freeze\":{\"epoch\":%llu,\"rng\":{\"hits\":%llu,\"bytes\":%llu},"
        "\"urandom\":{\"hits\":%llu,\"bytes\":%llu},"
        "\"clock_gettime\":{\"hits\":%llu},\"gettimeofday\":{\"hits\":%llu},"
        "\"time\":{\"hits\":%llu},\"getpid\":{\"hits\":%llu},\"gettid\":{\"hits\":%llu},"
        "\"vdso\":\"%s\",\"aslr\":\"%s\","
        "\"tsc\":{\"enabled\":%d,\"reads\":%llu,\"base\":\"%llx\",\"step\":%llu}}}\n",
        stat_.epoch_value, stat_.rng_hits, stat_.rng_bytes,
        stat_.urand_hits, stat_.urand_bytes,
        stat_.cgt_hits, stat_.gtd_hits, stat_.time_hits,
        stat_.pid_hits, stat_.tid_hits,
        vdso_s,
        opt.no_aslr ? "off" : "on",
        tscc.enabled, tscc.reads, tscc.base, tscc.step);
}

int main(int argc, char **argv) {
    const char *epoch_s = NULL;
    int sep = -1;
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "--")) { sep = i; break; }
        if (!strncmp(a, "--epoch=", 8)) epoch_s = a + 8;
        else if (!strncmp(a, "--rng-hex=", 10)) opt.rng_hex = a + 10;
        else if (!strncmp(a, "--urandom-hex=", 14)) opt.urandom_hex = a + 14;
        else if (!strncmp(a, "--pid=", 6)) opt.fixed_pid = atoll(a + 6);
        else if (!strncmp(a, "--tid=", 6)) opt.fixed_tid = atoll(a + 6);
        else if (!strcmp(a, "--keep-vdso")) opt.keep_vdso = 1;
        else if (!strcmp(a, "--freeze-monotonic")) opt.freeze_monotonic = 1;
        else if (!strcmp(a, "--no-aslr")) opt.no_aslr = 1;
        else if (!strcmp(a, "--quiet")) opt.quiet = 1;
        else if (!strcmp(a, "--no-rng")) opt.no_rng = 1;
        else if (!strcmp(a, "--no-clock")) opt.no_clock = 1;
        else if (!strcmp(a, "--no-atrandom")) opt.no_atrandom = 1;
        else if (!strcmp(a, "--no-getrandom")) opt.no_getrandom = 1;
        else if (!strcmp(a, "--no-urandom")) opt.no_urandom = 1;
        else if (!strcmp(a, "--log-syscalls")) opt.log_syscalls = 1;
        else if (!strcmp(a, "--watch-state")) opt.watch_state = 1;
        else if (!strncmp(a, "--watch-state-offsets=", 22)) {
            char *p = (char *)a + 22;
            sw_noff = 0;
            while (*p && sw_noff < 4) {
                sw_off[sw_noff++] = strtoul(p, &p, 0);
                if (*p == ',') p++;
                else break;
            }
            sw_off_given = sw_noff > 0;
        }
        else if (!strncmp(a, "--watch-fixed=", 14)) {
            char *p = (char *)a + 14;
            while (*p && sw_nfixed < 4) {
                sw_fixed[sw_nfixed++] = strtoul(p, &p, 16);
                if (*p == ',') p++;
                else break;
            }
        }
        else if (!strncmp(a, "--watch-scan-tag=", 17)) sw_scan_tag = a + 17;
        else if (!strncmp(a, "--watch-scan-offset=", 20))
            sw_scan_off = strtoul(a + 20, NULL, 0);
        else if (!strncmp(a, "--trace-dump-arg=", 17) ||
                 !strncmp(a, "--trace-dump-ret=", 17)) {
            int is_ret = a[13] == 'r';
            char *spec = (char *)a + 17;
            char *c1 = strchr(spec, ':');
            if (!c1) die("bad --trace-dump-arg/ret (REG[+OFF|@OFF]:SIZE:FILE)");
            *c1 = 0;
            char *c2 = strchr(c1 + 1, ':');
            if (!c2) die("bad --trace-dump-arg/ret (REG[+OFF|@OFF]:SIZE:FILE)");
            *c2 = 0;
            char *sep = strpbrk(spec, "+@");
            if (sep) *sep = 0;
            int ri = reg_index(spec);
            if (ri < 0) die("unknown register in --trace-dump-arg/ret");
            struct reg_dump *d = is_ret ? &rd_ret[nrd_ret] : &rd_arg[nrd_arg];
            if ((is_ret ? nrd_ret : nrd_arg) >= 8)
                die("too many --trace-dump-arg/ret");
            d->reg = ri;
            d->off = sep ? strtoll(sep + 1, NULL, 0) : 0;
            d->deref = sep && *sep == '@';
            d->size = strtoull(c1 + 1, NULL, 0);
            snprintf(d->tag, sizeof d->tag, "%s", c2 + 1);
            if (is_ret) nrd_ret++; else nrd_arg++;
        }
        else if (!strncmp(a, "--trace-fd=", 11)) {
            char *spec = (char *)a + 11;
            char *colon = strchr(spec, ':');
            if (!colon) die("bad --trace-fd (SUFFIX:DIR)");
            *colon = 0;
            iow.suffix = spec;
            iow.dir = colon + 1;
        }
        else if (!strncmp(a, "--scan-mem=", 11)) {
            if (nmscan >= 4) die("too many --scan-mem");
            char *spec = (char *)a + 11;
            char *colon = strchr(spec, ':');
            if (!colon) die("bad --scan-mem (HEX:TAG)");
            *colon = 0;
            int n = 0;
            for (char *p = spec; *p && n < 64; p += 2) {
                unsigned v = 0;
                if (sscanf(p, "%2x", &v) != 1) die("bad hex in --scan-mem");
                mscan[nmscan].pat[n++] = (unsigned char)v;
                if (!p[2]) break;
            }
            mscan[nmscan].len = n;
            snprintf(mscan[nmscan].tag, sizeof mscan[nmscan].tag, "%s", colon + 1);
            nmscan++;
        }
        else if (!strncmp(a, "--scan-at-path=", 15)) scan_at_path = a + 15;
        else if (!strncmp(a, "--scan-dir=", 11)) scan_dir = a + 11;
        else if (!strncmp(a, "--trace-lib=", 12)) { trc.lib_name = a + 12; trc.requested = 1; }
        else if (!strncmp(a, "--trace-rva=", 12)) { trc.rva = strtoul(a + 12, NULL, 0); trc.requested = 1; }
        else if (!strncmp(a, "--trace-out=", 12)) { trc.out_path = a + 12; trc.requested = 1; }
        else if (!strncmp(a, "--trace-max=", 12)) { trc.max_steps = strtoull(a + 12, NULL, 0); }
        else if (!strcmp(a, "--trace-noxs")) trc.no_xstate = 1;
        else if (!strcmp(a, "--trace-norec")) trc.no_rec = 1;
        else if (!strncmp(a, "--call-log=", 11)) { trc.calls_path = a + 11; trc.requested = 1; }
        else if (!strcmp(a, "--no-tsc-freeze")) opt.no_tsc_freeze = 1;
        else if (!strncmp(a, "--tsc-base=", 11)) opt.tsc_base = strtoull(a + 11, NULL, 0);
        else if (!strncmp(a, "--tsc-step=", 11)) opt.tsc_step = strtoull(a + 11, NULL, 0);
        else if (!strncmp(a, "--otp-buf=", 10)) opt.otp_buf = strtoull(a + 10, NULL, 0);
        else if (!strncmp(a, "--trace-mem=", 12)) {
            char spec[256];
            snprintf(spec, sizeof spec, "%s", a + 12);
            char *colon1 = strchr(spec, ':');
            char *colon2 = colon1 ? strchr(colon1 + 1, ':') : NULL;
            if (!colon1 || !colon2) die("bad --trace-mem (ADDR:SIZE:TAG)");
            *colon1 = 0; *colon2 = 0;
            if (nmregions >= MAX_MREGIONS) die("too many --trace-mem");
            mregions[nmregions].addr = strtoull(spec, NULL, 0);
            mregions[nmregions].size = strtoull(colon1 + 1, NULL, 0);
            nmregions++;
        }
        else if (!strncmp(a, "--trace-mem-out=", 16)) opt.mout_path = a + 16;
        else if (!strncmp(a, "--maps-out=", 11)) opt.maps_out = a + 11;
        else if (!strncmp(a, "--dump-mem=", 11)) {
            if (opt.ndumps >= 16) die("too many --dump-mem");
            char spec[256];
            snprintf(spec, sizeof spec, "%s", a + 11);
            char *colon1 = strchr(spec, ':');
            char *colon2 = colon1 ? strchr(colon1 + 1, ':') : NULL;
            if (!colon1 || !colon2) die("bad --dump-mem (ADDR:SIZE:TAG)");
            *colon1 = 0; *colon2 = 0;
            struct dump_range *d = &opt.dumps[opt.ndumps++];
            d->addr = strtoull(spec, NULL, 0);
            d->size = strtoull(colon1 + 1, NULL, 0);
            snprintf(d->tag, sizeof d->tag, "%s", colon2 + 1);
        }
        else if (!strncmp(a, "--dump-start=", 13)) {
            if (opt.nstartdumps >= 16) die("too many --dump-start");
            char spec[256];
            snprintf(spec, sizeof spec, "%s", a + 13);
            char *colon1 = strchr(spec, ':');
            char *colon2 = colon1 ? strchr(colon1 + 1, ':') : NULL;
            if (!colon1 || !colon2) die("bad --dump-start (ADDR:SIZE:TAG)");
            *colon1 = 0; *colon2 = 0;
            struct dump_range *d = &opt.sdumps[opt.nstartdumps++];
            d->addr = strtoull(spec, NULL, 0);
            d->size = strtoull(colon1 + 1, NULL, 0);
            snprintf(d->tag, sizeof d->tag, "%s", colon2 + 1);
        }
        else if (!strncmp(a, "--dump-rec=", 11)) {
            if (opt.nrdumps >= 256) die("too many --dump-rec");
            char spec[256];
            snprintf(spec, sizeof spec, "%s", a + 11);
            char *c1 = strchr(spec, ':'), *c2 = c1 ? strchr(c1 + 1, ':') : NULL,
                 *c3 = c2 ? strchr(c2 + 1, ':') : NULL;
            if (!c1 || !c2 || !c3) die("bad --dump-rec (IDX:ADDR:SIZE:TAG)");
            *c1 = 0; *c2 = 0; *c3 = 0;
            struct rdump *d = &opt.rdumps[opt.nrdumps++];
            d->rec = strtoull(spec, NULL, 0);
            d->addr = strtoull(c1 + 1, NULL, 0);
            d->size = strtoull(c2 + 1, NULL, 0);
            snprintf(d->tag, sizeof d->tag, "%s", c3 + 1);
        }
        else die("unknown option %s", a);
    }
    if (sep < 0 || sep + 1 >= argc)
        die("usage: adi_freeze [opts] -- PROG [ARGS...]");
    char **prog = argv + sep + 1;
    if (trc.requested && (!trc.lib_name || !trc.rva ||
                          (!trc.out_path && !trc.no_rec && !trc.calls_path)))
        die("--trace-lib, --trace-rva and --trace-out are required together");
    if (!trc.max_steps) trc.max_steps = 30000000;
    tscc.enabled = trc.requested && !opt.no_tsc_freeze;

    if (epoch_s) {
        char *end = NULL;
        opt.epoch = strtoll(epoch_s, &end, 10);
        if (end == epoch_s) die("bad --epoch");
    } else {
        struct timespec now;
        clock_gettime(CLOCK_REALTIME, &now);
        /* round down to a half-hour slot so replays in one session share it */
        opt.epoch = (long long)now.tv_sec - (now.tv_sec % 1800);
    }
    stat_.epoch_value = (unsigned long long)opt.epoch;
    init_stream(opt.rng_hex, stream, &stream_len);
    init_stream(opt.urandom_hex, ustream, &ustream_len);

    tscc.enabled = trc.requested && !opt.no_tsc_freeze;
    tscc.base = opt.tsc_base ? opt.tsc_base
                             : ((unsigned long long)opt.epoch << 21);
    tscc.step = opt.tsc_step ? opt.tsc_step : 4096;
    tscc.cur = tscc.base;

    pid_t pid = fork();
    if (pid < 0) die("fork: %s", strerror(errno));
    if (pid == 0) {
        if (opt.no_aslr && personality(ADDR_NO_RANDOMIZE) < 0) _exit(126);
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        raise(SIGSTOP);
        execvp(prog[0], prog);
        fprintf(stderr, "adi_freeze: exec %s: %s\n", prog[0], strerror(errno));
        _exit(127);
    }

    int status;
    if (waitpid(pid, &status, 0) < 0) die("waitpid: %s", strerror(errno));
    if (!WIFSTOPPED(status)) die("child did not stop as expected");
    unsigned long clo = (unsigned long)PTRACE_O_TRACECLONE |
                        (unsigned long)PTRACE_O_TRACEFORK |
                        (unsigned long)PTRACE_O_TRACEVFORK |
                        (unsigned long)PTRACE_O_TRACESYSGOOD |
                        (unsigned long)PTRACE_O_EXITKILL;
    if (ptrace(PTRACE_SETOPTIONS, pid, 0, (void *)clo) < 0)
        die("setoptions: %s", strerror(errno));
    ptrace(PTRACE_SYSCALL, pid, 0, 0);

    for (;;) {
        int st;
        pid_t w = waitpid(-1, &st, __WALL);
        if (w < 0) {
            if (errno == EINTR) continue;
            die("waitpid(-1): %s", strerror(errno));
        }
        if (WIFEXITED(st) || WIFSIGNALED(st)) {
            if (w == pid) {
                if (trc.out) fclose(trc.out);
                if (trc.calls) fclose(trc.calls);
                if (!opt.quiet) report();
                return WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st);
            }
            pstate_drop(w);
            forget_pid_fds(w);
            continue;
        }
        if (!WIFSTOPPED(st)) continue;
        int sig = WSTOPSIG(st);
        unsigned long ev = (unsigned long)st >> 16;

        if (sig == (SIGTRAP | 0x80)) {
            struct user_regs_struct r;
            if (ptrace(PTRACE_GETREGS, w, 0, &r) < 0) { ptrace(PTRACE_SYSCALL, w, 0, 0); continue; }
            struct pstate *ps = pstate_of(w);
            if (!ps) { ptrace(PTRACE_SYSCALL, w, 0, 0); continue; }
            state_watch_sync(w);
            if (!ps->in_syscall) {
                ps->in_syscall = 1;
                if (opt.log_syscalls) log_syscall(w, "E", (long)r.orig_rax, &r);
                handle_syscall_entry(w, &r);
                trace_try_arm(w);
            } else {
                ps->in_syscall = 0;
                if (opt.log_syscalls) log_syscall(w, "X", (long)r.orig_rax, &r);
                handle_syscall_exit(w, &r, (long)r.orig_rax);
            }
            /* a traced process must stay in single-step flow: resuming a
             * syscall boundary with PTRACE_SYSCALL would skip every
             * instruction up to the next syscall. */
            ptrace(ps->tracing ? PTRACE_SINGLESTEP : PTRACE_SYSCALL, w, 0, 0);
            continue;
        }
        if (sig == SIGTRAP) {
            state_watch_sync(w);
            if (ev == PTRACE_EVENT_CLONE || ev == PTRACE_EVENT_FORK || ev == PTRACE_EVENT_VFORK) {
                unsigned long msg = 0;
                ptrace(PTRACE_GETEVENTMSG, w, 0, &msg);
                ptrace(PTRACE_SYSCALL, w, 0, 0);
                if (msg) {
                    ptrace(PTRACE_SETOPTIONS, (pid_t)msg, 0, (void *)clo);
                    state_watch_sync((pid_t)msg);
                    ptrace(PTRACE_SYSCALL, (pid_t)msg, 0, 0);
                }
                continue;
            }
            if (ev == PTRACE_EVENT_EXIT) { ptrace(PTRACE_CONT, w, 0, 0); continue; }
            /* execve trap */
            struct pstate *ps = pstate_of(w);
            if (ps && !ps->exec_seen) {
                ps->exec_seen = 1;
                if (getenv("ADI_FREEZE_DEBUG_AUXV")) {
                    struct user_regs_struct dr;
                    if (ptrace(PTRACE_GETREGS, w, 0, &dr) == 0) {
                        fprintf(stderr, "[auxv-dbg] rsp=%llx\n", (unsigned long long)dr.rsp);
                        for (int k = 0; k < 48; k++) {
                            errno = 0;
                            long v = ptrace(PTRACE_PEEKDATA, w, dr.rsp + 8 * k, 0);
                            if (errno != 0) { fprintf(stderr, "[auxv-dbg] +%d unmapped\n", 8 * k); break; }
                            fprintf(stderr, "[auxv-dbg] rsp+%03d = %016lx\n", 8 * k, (unsigned long)v);
                        }
                    }
                }
                patch_auxv(w);
                ptrace(PTRACE_SYSCALL, w, 0, 0);
                continue;
            }
            /* ---- trace mode: int3 entry hit, then single-steps ---- */
            if (ps) trace_try_arm(w);
            if (ps && trc.requested && (trc.out || trc.no_rec)) {
                struct user_regs_struct r;
                if (ptrace(PTRACE_GETREGS, w, 0, &r) == 0) {
                    if (!ps->tracing && r.rip == trc.patch_addr + 1) {
                        /* INT3 at the trace entry: rewind, restore the byte,
                         * capture the return address, begin stepping. The
                         * engine's OTP work may complete on worker threads
                         * (libdispatch), so every existing thread steps too;
                         * the trace stops when the harness captures the
                         * outputs (mid.bin/otp.bin opens). */
                        r.rip = trc.patch_addr;
                        ptrace(PTRACE_SETREGS, w, 0, &r);
                        errno = 0;
                        long ow = ptrace(PTRACE_PEEKDATA, w, trc.patch_addr, 0);
                        if (errno == 0) {
                            long ow2 = (ow & ~0xffL) | trc.orig_byte;
                            ptrace(PTRACE_POKEDATA, w, trc.patch_addr, ow2);
                        }
                        trc.patched = 0;
                        errno = 0;
                        long ra = ptrace(PTRACE_PEEKDATA, w, (unsigned long)r.rsp, 0);
                        trc.retaddr = errno == 0 ? (unsigned long)ra : 0;
                        wp_arm(w, (unsigned long)r.rcx);
                        if (opt.otp_buf)
                            wp_watch_payload(w, (unsigned long)opt.otp_buf + 8);
                        trc.tracing = 1;
                        trc.steps = 0;
                        if (opt.maps_out) {
                            char mp[64];
                            snprintf(mp, sizeof mp, "/proc/%d/maps", w);
                            FILE *mi = fopen(mp, "r");
                            FILE *mo = mi ? fopen(opt.maps_out, "w") : NULL;
                            if (mi && mo) {
                                char ln[512];
                                while (fgets(ln, sizeof ln, mi))
                                    fputs(ln, mo);
                            }
                            if (mi) fclose(mi);
                            if (mo) fclose(mo);
                        }
                        mem_setup(w);
                        for (int i = 0; i < procs_n; i++) {
                            procs[i].tracing = 1;
                            procs[i].prev_valid = 0;
                        }
                        trace_write(w, &r, 1);
                        if (opt.nstartdumps)
                            dump_ranges(w, opt.sdumps, opt.nstartdumps);
                        fprintf(stderr, "[trace] entered tid=%d, retaddr=0x%lx args rdi=%llx rsi=%llx rdx=%llx rcx=%llx r8=%llx (all threads stepping)\n",
                                w, trc.retaddr, (unsigned long long)r.rdi, (unsigned long long)r.rsi,
                                (unsigned long long)r.rdx, (unsigned long long)r.rcx,
                                (unsigned long long)r.r8);
                        if (nrd_arg) dump_reg_dumps(w, &r, rd_arg, nrd_arg, "arg");
                        ptrace(PTRACE_SINGLESTEP, w, 0, 0);
                        continue;
                    }
                    if (ps->tracing) {
                        if (!trc.tracing) {
                            /* capture already ended the trace for everyone */
                            ps->tracing = 0;
                            ptrace(PTRACE_SYSCALL, w, 0, 0);
                            continue;
                        }
                        if (r.rip == trc.retaddr) {
                            trace_write(w, &r, 3);
                            ps->tracing = 0;
                            wp_disarm(w);
                            if (nrd_ret) dump_reg_dumps(w, &r, rd_ret, nrd_ret, "ret");
                            fprintf(stderr, "[trace] wrapper returned tid=%d after %llu records\n", w, trc.steps);
                            ptrace(PTRACE_SYSCALL, w, 0, 0);
                            continue;
                        }
                        if (trc.steps >= trc.max_steps) {
                            trace_write(w, &r, 4);
                            trace_stop_all(w);
                            fprintf(stderr, "[trace] step cap %llu hit tid=%d at ip=%llx\n",
                                    trc.max_steps, w, (unsigned long long)r.rip);
                            ptrace(PTRACE_SYSCALL, w, 0, 0);
                            continue;
                        }
                        /* freeze rdtsc/rdtscp: the instruction at prev_ip has
                         * just executed and left its counter in rax/rdx;
                         * replace it with the fake clock before the trace
                         * record so the log shows the value the engine sees.
                         * ALSO freeze time syscalls that crossed under
                         * single-step: PTRACE_SINGLESTEP executes the whole
                         * syscall without delivering boundary stops, so the
                         * boundary rewriter never saw it and the engine read
                         * the host clock (observed: gettimeofday at record
                         * ~240k of the traced window). The original pointer
                         * args survive the syscall, so rewrite in place. */
                        if (ps->prev_valid) {
                            errno = 0;
                            long iw = ptrace(PTRACE_PEEKDATA, w,
                                             ps->prev_ip, 0);
                            unsigned char b0 = errno == 0 ? (iw & 0xff) : 0;
                            unsigned char b1 = errno == 0 ? ((iw >> 8) & 0xff) : 0;
                            unsigned char b2 = errno == 0 ? ((iw >> 16) & 0xff) : 0;
                            if (errno == 0 && tscc.enabled &&
                                ((b0 == 0x0f && b1 == 0x31) ||   /* rdtsc  */
                                 (b0 == 0x0f && b1 == 0x01 && b2 == 0xf9))) {
                                r.rax = tscc.cur;
                                r.rdx = tscc.cur >> 32;
                                if (b0 == 0x0f && b1 == 0x01)
                                    r.rcx = 0;   /* rdtscp: TSC_AUX */
                                tscc.cur += tscc.step;
                                tscc.reads++;
                                ptrace(PTRACE_SETREGS, w, 0, &r);
                            } else if (errno == 0 && b0 == 0x0f && b1 == 0x05) {
                                long nr = (long)r.orig_rax;
                                if (nr == SYS_clock_gettime &&
                                    (unsigned)r.rdi == CLOCK_REALTIME) {
                                    freeze_clock_answer(w, (unsigned long)r.rsi);
                                    stat_.cgt_hits++;
                                } else if (nr == SYS_gettimeofday && r.rdi) {
                                    freeze_clock_answer(w, (unsigned long)r.rdi);
                                    stat_.gtd_hits++;
                                } else if (nr == SYS_time && r.rdi) {
                                    freeze_clock_answer(w, (unsigned long)r.rdi);
                                    r.rax = (unsigned long long)opt.epoch;
                                    ptrace(PTRACE_SETREGS, w, 0, &r);
                                    stat_.time_hits++;
                                }
                            }
                        }
                        trace_calllog(w, ps, (unsigned long long)r.rip);
                        ps->prev_ip = (unsigned long)r.rip;
                        ps->prev_valid = 1;
                        trc.steps++;
                        {
                            int mw = wp_check(w);
                            if (mw)
                                fprintf(stderr, "[trace] OTP payload store at prev_ip=%llx ip=%llx rax=%llx rbx=%llx rcx=%llx rdx=%llx\n",
                                        (unsigned long long)ps->prev_ip,
                                        (unsigned long long)r.rip,
                                        (unsigned long long)r.rax, (unsigned long long)r.rbx,
                                        (unsigned long long)r.rcx, (unsigned long long)r.rdx);
                            trace_write(w, &r, mw ? 5 : 2);
                            if (nmlr) {
                                /* libc is not lifted: carry the caller-visible
                                 * stores across the boundary as a delta log.
                                 * The record written just now is trc.steps - 1,
                                 * so the call/ret records are exact. */
                                int in_libc = mem_in_libc((unsigned long long)r.rip);
                                if (in_libc && !mem_prev_in_libc) {
                                    mem_call_rec = trc.steps - 1;
                                    mem_snapshot(w);
                                } else if (!in_libc && mem_prev_in_libc) {
                                    /* trace_write files the record whose ip
                                     * is r.rip, and trc.steps was advanced just
                                     * above: that record is rec_ret. */
                                    mem_deltas(w, trc.steps);
                                }
                                mem_prev_in_libc = in_libc;
                            }
                            for (int di = 0; di < opt.nrdumps; di++)
                                if (opt.rdumps[di].rec == trc.steps - 1)
                                    dump_ranges(w, (struct dump_range *)&opt.rdumps[di].addr, 1);
                        }
                        ptrace(PTRACE_SINGLESTEP, w, 0, 0);
                        continue;
                    }
                }
            }
            state_watch_hit(w);
            ptrace(PTRACE_SYSCALL, w, 0, 0);
            continue;
        }
        /* signal-delivery stop: pass the signal through */
        ptrace(PTRACE_SYSCALL, w, 0, (void *)(long)sig);
    }
}
