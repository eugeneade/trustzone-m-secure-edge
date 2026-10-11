/*
 * Polled LPUART1 output (PG7/PG8), routed by the NUCLEO-L552ZE-Q to the
 * ST-LINK virtual COM port at 115200 8N1.
 */
#ifndef UART_H
#define UART_H

#include <stdint.h>

void uart_init(void);
void uart_putc(char c);
void uart_puts(const char *s);          /* "\n" is sent as "\r\n" */
void uart_putu(uint32_t v);             /* unsigned decimal */
void uart_puthex(const uint8_t *p, uint32_t len);

#endif /* UART_H */
