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
    { INS_SELECT, "SELECT", scos_cmd_select },
    { INS_GET_RESPONSE, "GET RESPONSE", scos_cmd_get_response },
    { INS_READ_BINARY, "READ BINARY", scos_cmd_read_binary },
    { INS_UPDATE_BINARY, "UPDATE BINARY", scos_cmd_update_binary },
    { INS_CREATE_FILE, "CREATE FILE", scos_cmd_create_file },
    { INS_DELETE_FILE, "DELETE FILE", scos_cmd_delete_file },
    { INS_VERIFY, "VERIFY", scos_cmd_verify },
    { INS_CHANGE_REF_DATA, "CHANGE REFERENCE DATA", scos_cmd_change_ref_data },
    { INS_ACTIVATE_FILE, "ACTIVATE FILE", scos_cmd_activate_file },
    { INS_DEACTIVATE_FILE, "DEACTIVATE FILE", scos_cmd_deactivate_file },
};

uint16_t scos_dispatch(scos_kernel *k, const apdu_command *cmd,
                       apdu_response *rsp)
{
    if (k == NULL || cmd == NULL || rsp == NULL) {
        return SW_NO_PRECISE_DIAGNOSIS;
    }

    for (unsigned i = 0; i < (sizeof(k_commands) / sizeof(k_commands[0]));
         i++) {
        if (k_commands[i].ins == cmd->ins) {
            return k_commands[i].handler(k, cmd, rsp);
        }
    }
    return SW_INS_NOT_SUPPORTED; /* 6D00 */
}

const char *scos_ins_name(uint8_t ins)
{
    switch (ins) {
    case INS_SELECT:
        return "SELECT";
    case INS_GET_RESPONSE:
        return "GET RESPONSE";
    case INS_VERIFY:
        return "VERIFY";
    case INS_READ_BINARY:
        return "READ BINARY";
    case INS_UPDATE_BINARY:
        return "UPDATE BINARY";
    case INS_GET_DATA:
        return "GET DATA";
    case INS_CHANGE_REF_DATA:
        return "CHANGE REFERENCE DATA";
    case INS_CREATE_FILE:
        return "CREATE FILE";
    case INS_DELETE_FILE:
        return "DELETE FILE";
    case INS_ACTIVATE_FILE:
        return "ACTIVATE FILE";
    case INS_DEACTIVATE_FILE:
        return "DEACTIVATE FILE";
    default:
        return "UNKNOWN";
    }
}
