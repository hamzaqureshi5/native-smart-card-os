/* SPDX-License-Identifier: MIT
 *
 * scv1_internal.h -- Prototypes shared between the SCV1 HAL files.
 *
 * Not part of the HAL contract: nothing above include/hal/hal.h may include
 * this. It exists so every non-static function has a visible declaration,
 * which -Wmissing-prototypes enforces.
 */
#ifndef SCV1_INTERNAL_H
#define SCV1_INTERNAL_H

#include <stdint.h>

/* hal_arm_nvm.c */
void scv1_nvm_power_on(void);
void scv1_nvm_power_off(void);

/* hal_arm_io.c */
void scv1_uart_init(void);
void scv1_uart_puts(const char *s);

/* startup.c */
void scv1_reset_handler(void);

#endif /* SCV1_INTERNAL_H */
