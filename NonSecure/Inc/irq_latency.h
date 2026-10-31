/*
 * M5: Non-Secure interrupt latency while the CPU runs Non-Secure or Secure code.
 */
#ifndef IRQ_LATENCY_H
#define IRQ_LATENCY_H

/* Runs all scenarios and prints CSV rows (timer ticks = CPU cycles) on the UART. */
void irq_latency_run(void);

#endif /* IRQ_LATENCY_H */
