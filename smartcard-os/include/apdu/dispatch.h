/* SPDX-License-Identifier: MIT
 *
 * dispatch.h -- APDU command routing.
 *
 * A static, const command table. Static because the set of interindustry
 * commands is fixed at build time; const so it lands in ROM where an attacker
 * who achieves a RAM write cannot repoint a handler.
 */
#ifndef SCOS_DISPATCH_H
#define SCOS_DISPATCH_H

#include <stddef.h>
#include <stdint.h>

#include "apdu/apdu.h"
#include "os/kernel.h"

/* A handler validates its own P1/P2 and data, appends any response data to
 * *rsp, and RETURNS THE STATUS WORD. It must not write SW itself -- the
 * dispatcher does that, so every path is guaranteed to produce one. */
typedef uint16_t (*scos_cmd_handler)(scos_kernel *k,
                                     const apdu_command *cmd,
                                     apdu_response *rsp);

typedef struct {
    uint8_t          ins;
    const char      *name;   /* for tracing; not used in decisions */
    scos_cmd_handler handler;
} scos_cmd_entry;

/* Route cmd to a handler and return its status word. Returns 6D00 when the
 * instruction is unknown. CLA has already been validated by the caller. */
uint16_t scos_dispatch(scos_kernel *k, const apdu_command *cmd,
                       apdu_response *rsp);

/* Human-readable instruction name, or "UNKNOWN". Tracing only. */
const char *scos_ins_name(uint8_t ins);

/* --- ISO/IEC 7816-4 instruction codes implemented or planned ------------- */
#define INS_SELECT        0xA4u
#define INS_GET_RESPONSE  0xC0u
#define INS_VERIFY        0x20u
#define INS_READ_BINARY   0xB0u
#define INS_UPDATE_BINARY 0xD6u
#define INS_GET_DATA      0xCAu
#define INS_CREATE_FILE   0xE0u
#define INS_DELETE_FILE   0xE4u

/* --- handlers ----------------------------------------------------------- */
uint16_t scos_cmd_select(scos_kernel *k, const apdu_command *cmd,
                         apdu_response *rsp);
uint16_t scos_cmd_read_binary(scos_kernel *k, const apdu_command *cmd,
                              apdu_response *rsp);
uint16_t scos_cmd_update_binary(scos_kernel *k, const apdu_command *cmd,
                                apdu_response *rsp);

#endif /* SCOS_DISPATCH_H */
