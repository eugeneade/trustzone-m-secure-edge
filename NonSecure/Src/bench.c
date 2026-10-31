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

/* M4: Secure probes, each one more step of SECURE_MAC_Compute. */
__attribute__((noinline, noipa)) static void op_probe_args(uint32_t len)
{
  (void)SECURE_Probe_Args(msg, len, mac);
}

__attribute__((noinline, noipa)) static void op_probe_checks(uint32_t len)
{
  (void)SECURE_Probe_Checks(msg, len, mac);
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

/* hmac_sha256() alone, timed around the call inside each world, so call and
 * world-switch costs are excluded. Compares the same code in S and NS. */
static void measure_hmac_core(int secure, uint32_t len)
{
  for (uint32_t i = 0U; i < BENCH_WARMUP; i++)
  {
    (void)hmac_sha256(ns_key, sizeof(ns_key), msg, len, mac);
    (void)SECURE_Probe_HmacCycles(msg, len, mac);
  }

  __disable_irq();
  for (uint32_t i = 0U; i < BENCH_RUNS; i++)
  {
    if (secure)
    {
      samples[i] = SECURE_Probe_HmacCycles(msg, len, mac);
    }
    else
    {
      uint32_t t0 = DWT->CYCCNT;
      (void)hmac_sha256(ns_key, sizeof(ns_key), msg, len, mac);
      uint32_t t1 = DWT->CYCCNT;
      samples[i] = t1 - t0;
    }
  }
  __enable_irq();
}

static void report(const char *op, uint32_t len);

/* Steps of SECURE_MAC_Compute timed inside the Secure world. One pass per
 * step keeps a single samples[] buffer; every pass runs the full function. */
static void measure_mac_steps(uint32_t len)
{
  static const char *const names[SECURE_PROBE_STEPS] = {
    "step_checks", "step_hmac", "step_copy", "step_zeroize", "step_zeroize_mbedtls"
  };
  uint32_t steps[SECURE_PROBE_STEPS];

  for (uint32_t i = 0U; i < BENCH_WARMUP; i++)
  {
    (void)SECURE_Probe_MacSteps(msg, len, mac, steps);
  }

  for (uint32_t k = 0U; k < SECURE_PROBE_STEPS; k++)
  {
    __disable_irq();
    for (uint32_t i = 0U; i < BENCH_RUNS; i++)
    {
      (void)SECURE_Probe_MacSteps(msg, len, mac, steps);
      samples[i] = steps[k];
    }
    __enable_irq();
    report(names[k], len);
  }
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

static void sort_buf(uint32_t *buf, uint32_t n)
{
  for (uint32_t i = 1U; i < n; i++)
  {
    uint32_t v = buf[i];
    uint32_t j = i;
    while (j > 0U && buf[j - 1U] > v)
    {
      buf[j] = buf[j - 1U];
      j--;
    }
    buf[j] = v;
  }
}

/* Prints v/10 with one decimal, e.g. 1234 -> "123.4". */
static void put_x10(uint32_t v)
{
  uart_putu(v / 10U);
  uart_putc('.');
  uart_putc((char)('0' + (v % 10U)));
}

void bench_report(const char *op, uint32_t len, uint32_t *buf, uint32_t n)
{
  uint64_t sum = 0U;

  for (uint32_t i = 0U; i < n; i++)
  {
    sum += buf[i];
  }
  float mean = (float)sum / (float)n;

  float var = 0.0f;
  for (uint32_t i = 0U; i < n; i++)
  {
    float d = (float)buf[i] - mean;
    var += d * d;
  }
  float stddev = sqrtf(var / (float)(n - 1U));

  sort_buf(buf, n);
  uint32_t median_x10 = ((n % 2U) != 0U) ? buf[n / 2U] * 10U
                                         : (buf[n / 2U - 1U] + buf[n / 2U]) * 5U;

  uart_puts(op);
  uart_putc(',');
  uart_putu(len);
  uart_putc(',');
  uart_putu(n);
  uart_putc(',');
  uart_putu(buf[0]);
  uart_putc(',');
  put_x10(median_x10);
  uart_putc(',');
  put_x10((uint32_t)(mean * 10.0f + 0.5f));
  uart_putc(',');
  uart_putu(buf[n - 1U]);
  uart_putc(',');
  put_x10((uint32_t)(stddev * 10.0f + 0.5f));
  uart_puts("\n");
}

static void report(const char *op, uint32_t len)
{
  bench_report(op, len, samples, BENCH_RUNS);
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
      SECURE_MAC_Compute(msg, MSG_MAX, mac) != SECURE_OK ||
      SECURE_Probe_HmacCycles(msg, MSG_MAX, mac) == 0U ||
      SECURE_Probe_MacSteps(msg, MSG_MAX, mac, (uint32_t[SECURE_PROBE_STEPS]){0}) != SECURE_OK)
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

  /* M4: break the fixed Secure-service overhead into its steps. Two sizes
   * show whether any step depends on message length. */
  static const uint32_t probe_sizes[] = {64U, 1024U};

  for (uint32_t s = 0U; s < sizeof(probe_sizes) / sizeof(probe_sizes[0]); s++)
  {
    uint32_t len = probe_sizes[s];

    measure(op_probe_args, len);
    report("probe_args", len);

    measure(op_probe_checks, len);
    report("probe_checks", len);

    measure_mac_steps(len);

    measure_hmac_core(0, len);
    report("hmac_core_ns", len);

    measure_hmac_core(1, len);
    report("hmac_core_s", len);
  }
}
