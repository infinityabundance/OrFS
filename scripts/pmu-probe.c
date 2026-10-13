/*
 * Minimal hardware-PMU availability probe (not part of the orfs crate).
 *
 * Used by scripts/container-pmu.sh to PROVE, at run time, whether the
 * container's seccomp profile permits `perf_event_open` for a *user-space*
 * per-thread hardware counter. Exits 0 when such a counter can be opened and
 * read; exits non-zero (with the errno) when the syscall is blocked.
 *
 * This mirrors scripts/uring-probe.c. Note the semantics that the probe makes
 * concrete: `perf_event_paranoid=2` denies only *kernel* profiling to an
 * unprivileged caller; a user-space event (`exclude_kernel=1`) for the calling
 * thread (`pid=0`, `cpu=-1`) is still permitted. The usual real blocker is the
 * container seccomp profile, which denies the syscall outright with EPERM.
 *
 * Build/run under the default profile:
 *   cc scripts/pmu-probe.c -o /tmp/probe && /tmp/probe
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <linux/perf_event.h>

#ifndef __NR_perf_event_open
#define __NR_perf_event_open 298
#endif

static int open_hw(uint64_t config) {
    struct perf_event_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.type = PERF_TYPE_HARDWARE;
    attr.size = sizeof(attr);
    attr.config = config;
    attr.disabled = 1;
    attr.exclude_kernel = 1;
    attr.exclude_hv = 1;
    return (int)syscall(__NR_perf_event_open, &attr, 0, -1, -1, 0);
}

int main(void) {
    int fd = open_hw(PERF_COUNT_HW_INSTRUCTIONS);
    if (fd < 0) {
        printf("perf_event_open(HW_INSTRUCTIONS): FAIL errno=%d (%s)\n",
               errno, strerror(errno));
        return 1;
    }
    printf("perf_event_open(HW_INSTRUCTIONS): OK fd=%d\n", fd);

    if (ioctl(fd, PERF_EVENT_IOC_RESET, 0) != 0 ||
        ioctl(fd, PERF_EVENT_IOC_ENABLE, 0) != 0) {
        printf("ioctl(ENABLE): FAIL errno=%d (%s)\n", errno, strerror(errno));
        return 1;
    }

    volatile uint64_t x = 0;
    for (uint64_t i = 0; i < 1000000; i++) x += i;

    if (ioctl(fd, PERF_EVENT_IOC_DISABLE, 0) != 0) {
        printf("ioctl(DISABLE): FAIL errno=%d (%s)\n", errno, strerror(errno));
        return 1;
    }

    uint64_t val = 0;
    if (read(fd, &val, sizeof(val)) != (ssize_t)sizeof(val)) {
        printf("read(counter): FAIL errno=%d (%s)\n", errno, strerror(errno));
        return 1;
    }
    printf("instructions counted: %llu\n", (unsigned long long)val);
    close(fd);
    return 0;
}
