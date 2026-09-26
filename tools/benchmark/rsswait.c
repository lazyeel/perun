/* Measure a child without inheriting the parent's high-water mark.
 *
 * Why not Python: fork()+exec() makes the child inherit the parent's
 * high-water mark. The kernel copies mm->hiwater_rss into the duplicated mm
 * and exec_mmap() folds it into signal->maxrss, so a Python parent reports
 * 5752 KiB for /bin/true. This measurer's own RSS is ~1.2 MiB, so the peak it
 * reports is the measured program's plus a known floor.
 *
 * The child's stdout and stderr are inherited, so the program's own
 * diagnostics come back on the same pipes. The measurement goes to **stderr**
 * as a single parseable line, so stdout carries nothing but the program's
 * output:
 *
 *   M rss_kib=1234 user_ms=45 sys_ms=12 wall_ms=250 status=0
 *
 * where `wall_ms` is this measurer's own clock around the child, and the exit
 * status mirrors the child's (exit code, or 128+signal).
 */
/* `_DEFAULT_SOURCE`, not `_POSIX_C_SOURCE`: under a strict POSIX feature set
 * glibc hides `wait4(2)`, which is the whole point of this program. */
#define _DEFAULT_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

static double ms(struct timeval tv) {
    return tv.tv_sec * 1000.0 + tv.tv_usec / 1000.0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: rsswait <program> [args...]\n");
        return 2;
    }
    struct timeval t0, t1;
    gettimeofday(&t0, NULL);
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return 3;
    }
    if (pid == 0) {
        execvp(argv[1], argv + 1);
        fprintf(stderr, "rsswait: exec %s: %s\n", argv[1], strerror(errno));
        _exit(127);
    }
    int status = 0;
    struct rusage ru;
    if (wait4(pid, &status, 0, &ru) < 0) {
        perror("wait4");
        return 3;
    }
    gettimeofday(&t1, NULL);
    int code;
    if (WIFEXITED(status)) {
        code = WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        code = 128 + WTERMSIG(status);
    } else {
        code = 4;
    }
    fprintf(stderr, "M rss_kib=%ld user_ms=%.0f sys_ms=%.0f wall_ms=%.0f status=%d\n",
            ru.ru_maxrss, ms(ru.ru_utime), ms(ru.ru_stime),
            ms((struct timeval){t1.tv_sec - t0.tv_sec,
                                t1.tv_usec - t0.tv_usec}),
            code);
    return code;
}
