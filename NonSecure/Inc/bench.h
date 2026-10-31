/*
 * M3/M4: latency of Secure-world calls and of HMAC in each world.
 */
#ifndef BENCH_H
#define BENCH_H

#include <stdint.h>

/* Runs all call/HMAC benchmarks and prints CSV rows (cycles) on the UART.
 * The caller prints the closing "# end" line once all benchmarks are done. */
void bench_run(void);

/* Prints one CSV row (op,bytes,runs,min,median,mean,max,stddev) for buf[0..n).
 * Sorts buf in place. */
void bench_report(const char *op, uint32_t len, uint32_t *buf, uint32_t n);

#endif /* BENCH_H */
