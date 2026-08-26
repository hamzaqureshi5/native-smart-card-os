/* SPDX-License-Identifier: MIT
 *
 * apdu_dispatch.c -- Instruction routing.
 */
#include "apdu/dispatch.h"

#include "apdu/sw.h"

/* const so the linker places it in ROM. On real silicon that matters: a
 * writable handler table is a single-write-primitive away from arbitrary code
 * execution. */
static const scos_cmd_entry k_commands[] = {
    { INS_SELECT,        "SELECT",        scos_cmd_select        },
    { INS_READ_BINARY,   "READ BINARY",   scos_cmd_read_binary   },
    { INS_UPDATE_BINARY, "UPDATE BINARY", scos_cmd_update_binary },
    /* M2b adds CREATE FILE / DELETE FILE / GET RESPONSE;
     * M3 adds VERIFY. */
};

uint16_t scos_dispatch(scos_kernel *k, const apdu_command *cmd,
                       apdu_response *rsp)
{
    if (k == NULL || cmd == NULL || rsp == NULL) {
        return SW_NO_PRECISE_DIAGNOSIS;
    }

    for (unsigned i = 0; i < (sizeof(k_commands) / sizeof(k_commands[0])); i++) {
        if (k_commands[i].ins == cmd->ins) {
            return k_commands[i].handler(k, cmd, rsp);
        }
    }
    return SW_INS_NOT_SUPPORTED; /* 6D00 */
}

const char *scos_ins_name(uint8_t ins)
{
    switch (ins) {
    case INS_SELECT:        return "SELECT";
    case INS_GET_RESPONSE:  return "GET RESPONSE";
    case INS_VERIFY:        return "VERIFY";
    case INS_READ_BINARY:   return "READ BINARY";
    case INS_UPDATE_BINARY: return "UPDATE BINARY";
    case INS_GET_DATA:      return "GET DATA";
    case INS_CREATE_FILE:   return "CREATE FILE";
    case INS_DELETE_FILE:   return "DELETE FILE";
    default:                return "UNKNOWN";
    }
}
