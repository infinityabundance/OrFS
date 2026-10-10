/*
 * Minimal io_uring availability probe (not part of the orfs crate).
 *
 * Used by scripts/container-uring-test.sh to PROVE, at run time, whether the
 * container's seccomp profile permits io_uring_setup. Exits 0 when io_uring is
 * usable and prints the ring features; exits non-zero (with the errno) when the
 * syscall is blocked.
 *
 * Build/run under the default profile:
 *   cc scripts/uring-probe.c -o /tmp/probe && /tmp/probe
 */
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/io_uring.h>

#ifndef __NR_io_uring_setup
#define __NR_io_uring_setup 425
#endif

int main(void) {
    struct io_uring_params p;
    memset(&p, 0, sizeof(p));
    long fd = syscall(__NR_io_uring_setup, 8, &p);
    if (fd < 0) {
        printf("io_uring_setup: FAIL errno=%d (%s)\n", errno, strerror(errno));
        return 1;
    }
    printf("io_uring_setup: OK fd=%ld features=0x%x\n", fd, p.features);
    close((int)fd);
    return 0;
}
