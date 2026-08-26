/* SPDX-License-Identifier: MIT
 *
 * semihost.h -- ARM semihosting, used ONLY for host file access.
 *
 * Semihosting is a debug protocol: the firmware executes BKPT 0xAB and the
 * debugger or emulator services the request. We use it for exactly one thing:
 * loading and saving the virtual NVM images, which is how a development target
 * fakes persistence it does not have.
 *
 * IT IS NOT PART OF THE CARD. A real SCV1 would program its own flash through
 * a flash controller, and no semihosting call would exist. Card I/O
 * deliberately does NOT use semihosting -- it goes through the UART, because
 * that is a real peripheral and the abstraction we want to exercise.
 */
#ifndef SCV1_SEMIHOST_H
#define SCV1_SEMIHOST_H

#include <stdbool.h>
#include <stdint.h>

/*
 * True if a semihosting host is answering.
 *
 * DETECTING THIS IS HARDER THAN IT LOOKS, and getting it wrong was a real bug
 * here. There is no status register to read: the only way to ask is to execute
 * BKPT 0xAB and see what happens. With a host attached, the host services it.
 * With no host -- a production card, or QEMU without -semihosting-config -- the
 * breakpoint raises a debug exception that escalates to a HardFault. So the
 * probe *causes* the failure it is trying to detect, and a naive implementation
 * bricks the card on boot.
 *
 * The fix is the standard bare-metal one: arm the fault handler first, then
 * execute the instruction. If the fault fires, the handler steps the stacked PC
 * over the 2-byte BKPT and records "no host", and execution resumes normally.
 * See scv1_fault_c() in startup.c.
 */
bool semihost_available(void);
void semihost_probe(void);

/* --- probe protocol, between semihost.c and the fault handler ------------ */

/* Non-zero while a probe BKPT is in flight, so the fault handler knows the
 * fault is expected rather than an attack or a bug. */
int  semihost_probe_in_flight(void);

/* Called BY THE FAULT HANDLER when the probe faulted: no host is present. */
void semihost_probe_faulted(void);

/* Returns bytes read, or -1. Opens read-only; a missing file is not an error,
 * it means "factory blank". */
long semihost_load(const char *path, void *dst, uint32_t len);

/* Returns 0 on success, -1 otherwise. Truncates and rewrites. */
int semihost_store(const char *path, const void *src, uint32_t len);

/* Terminate the emulator, so a scripted run can exit cleanly. */
void semihost_exit(int code);

#endif /* SCV1_SEMIHOST_H */
