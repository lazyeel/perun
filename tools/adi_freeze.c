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
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/personality.h>
#include <sys/ptrace.h>
#include <sys/types.h>
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

#define AT_SYSINFO_EHDR    33
#define AT_RANDOM          25
#define CLOCK_REALTIME     0

#define MAX_PID_SLOTS 256

/* ---- options / counters -------------------------------------------------- */

static struct {
    long long epoch;          /* fixed realtime seconds; -1 = derive from host */
    const char *rng_hex;
    const char *urandom_hex;
    long long fixed_pid;
    long long fixed_tid;
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
} opt;

static struct {
    unsigned long long rng_hits, rng_bytes;
    unsigned long long urand_hits, urand_bytes;
    unsigned long long cgt_hits, gtd_hits, time_hits, pid_hits, tid_hits;
    unsigned long long epoch_value;
    int vdso_scan_ok;         /* auxv scan found the vDSO entry at all */
    int vdso_patched;         /* and the zero-write was verified */
} stat_;

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

/* ---- per-process state ----------------------------------------------------- */

struct pstate {
    pid_t pid;
    int in_syscall;          /* 0 = last stop was entry, 1 = exit pending */
    int open_is_urandom;     /* flagged at open entry, consumed at open exit */
    int exec_seen;
    long close_fd;           /* fd seen at close/dup entry */
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
    case SYS_pread64:
        if (is_urandom_fd(pid, (long)r->rdi) && !opt.no_rng && !opt.no_urandom)
            fill_stream(pid, (unsigned long)r->rsi, (unsigned long)r->rax,
                        ustream, ustream_len, &stat_.urand_hits, &stat_.urand_bytes);
        break;
    case SYS_open:
    case SYS_openat: {
        struct pstate *ps = pstate_of(pid);
        if (ps && ps->open_is_urandom && r->rax >= 0 && r->rax < 0x7fffffff)
            mark_urandom_fd(pid, (int)r->rax);
        if (ps) ps->open_is_urandom = 0;
        break;
    }
    case SYS_close: {
        /* fd lifecycle tracking: a closed urandom fd must leave the table or
         * its number will be silently reused by the next open and our fill
         * would poison an unrelated read (this corrupted adi.pb reads). */
        struct pstate *ps = pstate_of(pid);
        if (ps && ps->close_fd >= 0 && r->rax == 0)
            forget_urandom_fd(pid, (int)ps->close_fd);
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
    if (nr == SYS_open || nr == SYS_openat) {
        unsigned long patharg = nr == SYS_open ? (unsigned long)r->rdi : (unsigned long)r->rsi;
        char path[128];
        read_child_string(pid, patharg, path, sizeof path);
        ps->open_is_urandom = !strcmp(path, "/dev/urandom") || !strcmp(path, "/dev/random");
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
        "\"vdso\":\"%s\",\"aslr\":\"%s\"}}\n",
        stat_.epoch_value, stat_.rng_hits, stat_.rng_bytes,
        stat_.urand_hits, stat_.urand_bytes,
        stat_.cgt_hits, stat_.gtd_hits, stat_.time_hits,
        stat_.pid_hits, stat_.tid_hits,
        vdso_s,
        opt.no_aslr ? "off" : "on");
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
        else die("unknown option %s", a);
    }
    if (sep < 0 || sep + 1 >= argc)
        die("usage: adi_freeze [opts] -- PROG [ARGS...]");
    char **prog = argv + sep + 1;

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
            if (!ps->in_syscall) {
                ps->in_syscall = 1;
                if (opt.log_syscalls) log_syscall(w, "E", (long)r.orig_rax, &r);
                handle_syscall_entry(w, &r);
            } else {
                ps->in_syscall = 0;
                if (opt.log_syscalls) log_syscall(w, "X", (long)r.orig_rax, &r);
                handle_syscall_exit(w, &r, (long)r.orig_rax);
            }
            ptrace(PTRACE_SYSCALL, w, 0, 0);
            continue;
        }
        if (sig == SIGTRAP) {
            if (ev == PTRACE_EVENT_CLONE || ev == PTRACE_EVENT_FORK || ev == PTRACE_EVENT_VFORK) {
                unsigned long msg = 0;
                ptrace(PTRACE_GETEVENTMSG, w, 0, &msg);
                ptrace(PTRACE_SYSCALL, w, 0, 0);
                if (msg) {
                    ptrace(PTRACE_SETOPTIONS, (pid_t)msg, 0, (void *)clo);
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
            }
            ptrace(PTRACE_SYSCALL, w, 0, 0);
            continue;
        }
        /* signal-delivery stop: pass the signal through */
        ptrace(PTRACE_SYSCALL, w, 0, (void *)(long)sig);
    }
}
