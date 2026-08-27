/* SPDX-License-Identifier: MIT */
#include "semihost.h"

#define SYS_OPEN  0x01
#define SYS_CLOSE 0x02
#define SYS_WRITE 0x05
#define SYS_READ  0x06
#define SYS_SEEK  0x0A
#define SYS_EXIT  0x18

/* Semihosting call: operation in r0, parameter block pointer in r1, result in
 * r0. BKPT 0xAB is the agreed trap. */
static long sh_call(int op, void *arg)
{
    register long  r0 __asm__("r0") = (long)op;
    register void *r1 __asm__("r1") = arg;
    __asm__ volatile("bkpt 0xAB" : "+r"(r0) : "r"(r1) : "memory");
    return r0;
}

static bool s_available = false;
static bool s_probed    = false;

/* volatile: written by the fault handler, read by ordinary code. Without this
 * the compiler is entitled to assume nothing changes it and hoist the read. */
static volatile int s_probe_in_flight = 0;

int semihost_probe_in_flight(void)
{ return s_probe_in_flight; }
void semihost_probe_faulted(void)
{
    s_probe_in_flight = 0;
    s_available       = false;
}

/* Open modes from the semihosting specification. */
#define MODE_RB 0 /* "rb" */
#define MODE_WB 4 /* "wb" */

static long sh_open(const char *path, int mode)
{
    /* The parameter block is (pointer, mode, length-of-path). */
    uint32_t block[3];
    uint32_t n = 0u;
    while (path[n] != '\0') {
        n++;
    }
    block[0] = (uint32_t)(uintptr_t)path;
    block[1] = (uint32_t)mode;
    block[2] = n;
    return sh_call(SYS_OPEN, block);
}

static long sh_close(long fd)
{
    uint32_t block[1] = { (uint32_t)fd };
    return sh_call(SYS_CLOSE, block);
}

void semihost_probe(void)
{
    if (s_probed) {
        return;
    }
    s_probed = true;

    /*
     * Arm the fault trap, then execute the probe. If no host is present the
     * BKPT faults, the handler clears this flag and steps over the
     * instruction, and sh_open() returns whatever happened to be in r0 --
     * which we must NOT trust. So the flag, not the return value, decides.
     */
    s_probe_in_flight = 1;
    s_available       = true; /* provisional; the fault handler revokes it */

    const long fd = sh_open(":tt", MODE_RB);

    if (s_probe_in_flight == 0) {
        /* The handler fired: no semihosting host. NVM will be volatile. */
        s_available = false;
        return;
    }
    s_probe_in_flight = 0;

    /* A host answered. Some return 0 for stdin, so only a negative result
     * means the open genuinely failed. */
    if (fd > 0) {
        (void)sh_close(fd);
        s_available = true;
    } else {
        s_available = (fd == 0);
    }
}

bool semihost_available(void)
{ return s_available; }

long semihost_load(const char *path, void *dst, uint32_t len)
{
    if (!s_available) {
        return -1;
    }
    const long fd = sh_open(path, MODE_RB);
    if (fd <= 0) {
        return -1; /* absent: a factory-blank chip, not an error */
    }

    /* SYS_READ returns the number of bytes NOT read, which is the opposite of
     * every other read API and a reliable source of bugs. */
    uint32_t block[3];
    block[0]            = (uint32_t)fd;
    block[1]            = (uint32_t)(uintptr_t)dst;
    block[2]            = len;
    const long not_read = sh_call(SYS_READ, block);
    (void)sh_close(fd);

    if (not_read < 0) {
        return -1;
    }
    if ((uint32_t)not_read > len) {
        return -1;
    }
    return (long)(len - (uint32_t)not_read);
}

int semihost_store(const char *path, const void *src, uint32_t len)
{
    if (!s_available) {
        return -1;
    }
    const long fd = sh_open(path, MODE_WB);
    if (fd <= 0) {
        return -1;
    }
    uint32_t block[3];
    block[0]               = (uint32_t)fd;
    block[1]               = (uint32_t)(uintptr_t)src;
    block[2]               = len;
    const long not_written = sh_call(SYS_WRITE, block);
    (void)sh_close(fd);
    return (not_written == 0) ? 0 : -1;
}

void semihost_exit(int code)
{
    if (!s_available) {
        return;
    }
    /* ADP_Stopped_ApplicationExit. */
    (void)code;
    (void)sh_call(SYS_EXIT, (void *)0x20026u);
}
