/*
 * M3 benchmark: what does moving a function into the Secure world cost?
 *
 * Every operation is timed with the DWT cycle counter around a call through
 * the same function-pointer harness, BENCH_RUNS times after BENCH_WARMUP
 * untimed runs (instruction cache warm). Cycles are reported raw; the costs
 * of interest are differences between rows:
 *
 *   NS -> S -> NS transition  = nsc_call_empty - ns_call_empty
 *   cost of the Secure MAC    = hmac_nsc - hmac_ns   (same code, same size;
 *     includes transition, cmse pointer checks and the copy-out of the tag)
 *
 * Each op wrapper makes exactly one further call (to an NS function, or to an
 * NSC veneer), so the two sides of each difference have the same call depth.
 * Interrupts are masked while measuring.
 */
#include <math.h>
#include <stddef.h>
#include "stm32l5xx.h"
#include "secure_nsc.h"
#include "hmac_sha256.h"
#include "bench.h"
#include "uart.h"

#define BENCH_RUNS    1000U
#define BENCH_WARMUP  10U
#define MSG_MAX       1024U

typedef void (*bench_op_t)(uint32_t len);

static uint32_t samples[BENCH_RUNS];
static uint8_t msg[MSG_MAX];
static uint8_t mac[HMAC_SHA256_SIZE];

/* NS-side key for the baseline only; it plays no part in the Secure service. */
static const uint8_t ns_key[32] = {
  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
  0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f
};

/* ------------------------------ Operations -------------------------------- */

__attribute__((noinline, noipa)) static void ns_nop(void)
{
  __asm volatile ("" ::: "memory");
}

__attribute__((noinline, noipa)) static void op_ns_call_empty(uint32_t len)
{
  (void)len;
  ns_nop();
}

__attribute__((noinline, noipa)) static void op_nsc_call_empty(uint32_t len)
{
  (void)len;
  SECURE_Nop();
}

__attribute__((noinline, noipa)) static void op_hmac_ns(uint32_t len)
{
  (void)hmac_sha256(ns_key, sizeof(ns_key), msg, len, mac);
}

__attribute__((noinline, noipa)) static void op_hmac_nsc(uint32_t len)
{
  (void)SECURE_MAC_Compute(msg, len, mac);
}

/* ----------------------------- Measurement -------------------------------- */

static void measure(bench_op_t op, uint32_t len)
{
  for (uint32_t i = 0U; i < BENCH_WARMUP; i++)
  {
    op(len);
  }

  __disable_irq();
  for (uint32_t i = 0U; i < BENCH_RUNS; i++)
  {
    uint32_t t0 = DWT->CYCCNT;
    op(len);
    uint32_t t1 = DWT->CYCCNT;
    samples[i] = t1 - t0;
  }
  __enable_irq();
}

/* Back-to-back counter reads: the fixed cost of the timing itself. */
static void measure_timer_only(void)
{
  __disable_irq();
  for (uint32_t i = 0U; i < BENCH_RUNS; i++)
  {
    uint32_t t0 = DWT->CYCCNT;
    __asm volatile ("" ::: "memory");
    uint32_t t1 = DWT->CYCCNT;
    samples[i] = t1 - t0;
  }
  __enable_irq();
}

/* ------------------------------- Reporting -------------------------------- */

static void sort_samples(void)
{
  for (uint32_t i = 1U; i < BENCH_RUNS; i++)
  {
    uint32_t v = samples[i];
    uint32_t j = i;
    while (j > 0U && samples[j - 1U] > v)
    {
      samples[j] = samples[j - 1U];
      j--;
    }
    samples[j] = v;
  }
}

/* Prints v/10 with one decimal, e.g. 1234 -> "123.4". */
static void put_x10(uint32_t v)
{
  uart_putu(v / 10U);
  uart_putc('.');
  uart_putc((char)('0' + (v % 10U)));
}

static void report(const char *op, uint32_t len)
{
  uint64_t sum = 0U;

  for (uint32_t i = 0U; i < BENCH_RUNS; i++)
  {
    sum += samples[i];
  }
  float mean = (float)sum / (float)BENCH_RUNS;

  float var = 0.0f;
  for (uint32_t i = 0U; i < BENCH_RUNS; i++)
  {
    float d = (float)samples[i] - mean;
    var += d * d;
  }
  float stddev = sqrtf(var / (float)(BENCH_RUNS - 1U));

  sort_samples();
  /* Even run count: median is the mean of the two middle samples. */
  uint32_t median_x10 = (samples[BENCH_RUNS / 2U - 1U] + samples[BENCH_RUNS / 2U]) * 5U;

  uart_puts(op);
  uart_putc(',');
  uart_putu(len);
  uart_putc(',');
  uart_putu(BENCH_RUNS);
  uart_putc(',');
  uart_putu(samples[0]);
  uart_putc(',');
  put_x10(median_x10);
  uart_putc(',');
  put_x10((uint32_t)(mean * 10.0f + 0.5f));
  uart_putc(',');
  uart_putu(samples[BENCH_RUNS - 1U]);
  uart_putc(',');
  put_x10((uint32_t)(stddev * 10.0f + 0.5f));
  uart_puts("\n");
}

void bench_run(void)
{
  static const uint32_t sizes[] = {16U, 64U, 256U, 1024U};

  for (uint32_t i = 0U; i < MSG_MAX; i++)
  {
    msg[i] = (uint8_t)i;
  }

  /* The timed loop ignores return codes, so make sure the ops really succeed. */
  if (hmac_sha256(ns_key, sizeof(ns_key), msg, MSG_MAX, mac) != 0 ||
      SECURE_MAC_Compute(msg, MSG_MAX, mac) != SECURE_OK)
  {
    uart_puts("\nM3: benchmark aborted, HMAC operation failed\n");
    return;
  }

  uart_puts("\nM3: benchmark (cycles)\n");
  uart_puts("# sysclk_hz=");
  uart_putu(SystemCoreClock);
  uart_puts("\n# icache=");
  uart_putu((ICACHE->CR & ICACHE_CR_EN) != 0U ? 1U : 0U);
  uart_puts("\n# runs=");
  uart_putu(BENCH_RUNS);
  uart_puts(" warmup=");
  uart_putu(BENCH_WARMUP);
  uart_puts("\nop,bytes,runs,min,median,mean,max,stddev\n");

  measure_timer_only();
  report("timer_only", 0U);

  measure(op_ns_call_empty, 0U);
  report("ns_call_empty", 0U);

  measure(op_nsc_call_empty, 0U);
  report("nsc_call_empty", 0U);

  for (uint32_t s = 0U; s < sizeof(sizes) / sizeof(sizes[0]); s++)
  {
    measure(op_hmac_ns, sizes[s]);
    report("hmac_ns", sizes[s]);

    measure(op_hmac_nsc, sizes[s]);
    report("hmac_nsc", sizes[s]);
  }

  uart_puts("# end\n");
}
