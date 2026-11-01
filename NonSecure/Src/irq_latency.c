/*
 * M5 benchmark: how late is a Non-Secure interrupt when it arrives while the
 * CPU is executing Secure code?
 *
 * TIM2 counts at the CPU clock (APB1 /1, prescaler 0) and raises an update
 * interrupt every IRQ_PERIOD cycles. The counter restarts from 0 at the update
 * event, so the first thing the handler does, read TIM2->CNT, gives the cycles
 * from the event to the handler (exception entry + handler prologue + one
 * peripheral read; the last two are the same in every scenario).
 *
 * IRQ_PERIOD is prime so that, over IRQ_SAMPLES interrupts, the event lands at
 * many different points of the foreground loop. The foreground workload in
 * each scenario runs until IRQ_SAMPLES interrupts have been recorded:
 *
 *   irq_idle_ns     NS busy loop                       baseline
 *   irq_hmac_ns     HMAC-SHA256 (1 KB) in NS           NS code under load
 *   irq_hmac_s      SECURE_MAC_Compute (1 KB)          interrupt preempts Secure code
 *   irq_nop_s       SECURE_Nop in a loop               lands in/around world switches
 *   irq_hmac_hw_s   SECURE_MAC_ComputeHw (1 KB)        M6: HASH peripheral busy
 *
 * M6 also runs a contention test (contention_run) on the shared peripheral.
 *
 * Max is the figure of interest for real-time use.
 */
#include <stddef.h>
#include <string.h>
#include "stm32l5xx.h"
#include "secure_nsc.h"
#include "hmac_sha256.h"
#include "bench.h"
#include "irq_latency.h"
#include "uart.h"

#define IRQ_SAMPLES  1000U
#define IRQ_PERIOD   7919U     /* prime, in CPU cycles */
#define IRQ_MSG_LEN  1024U

static volatile uint32_t irq_count;
static uint32_t irq_samples[IRQ_SAMPLES];
static volatile uint32_t irq_first_cyc;
static volatile uint32_t irq_last_cyc;

/* M6 diagnosis: driver phase at each interrupt (see hash_phase_t). */
static volatile uint32_t hw_phase;
static volatile uint32_t phase_mode;
static uint8_t irq_phase[IRQ_SAMPLES];
static uint32_t phase_samples[IRQ_SAMPLES];

static uint8_t msg[IRQ_MSG_LEN] __attribute__((aligned(4)));   /* aligned: HASH DMA path */
static uint8_t mac[HMAC_SHA256_SIZE];

static const uint8_t ns_key[32] = {
  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
  0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f
};

/* M6 contention test: the handler also asks for a hardware MAC, possibly while
 * the foreground's hardware MAC is suspended mid-computation. */
#define CONTENTION_MSG_LEN  16U

static volatile uint32_t contention_mode;
static volatile uint32_t contention_ok;
static volatile uint32_t contention_busy;
static volatile uint32_t contention_errors;
static uint8_t contention_mac[HMAC_SHA256_SIZE];
static uint8_t contention_ref[HMAC_SHA256_SIZE];

static void contention_handler_call(void)
{
  secure_status_t st = SECURE_MAC_ComputeHw(msg, CONTENTION_MSG_LEN, contention_mac);

  if (st == SECURE_ERR_BUSY)
  {
    contention_busy++;
  }
  else if (st == SECURE_OK && memcmp(contention_mac, contention_ref, sizeof(contention_ref)) == 0)
  {
    contention_ok++;
  }
  else
  {
    contention_errors++;
  }
}

void TIM2_IRQHandler(void)
{
  uint32_t ticks = TIM2->CNT;   /* first: cycles since the update event */
  uint32_t now = DWT->CYCCNT;

  TIM2->SR = ~TIM_SR_UIF;
  (void)TIM2->SR;               /* flag clear lands before exception return */

  if (contention_mode != 0U && irq_count < IRQ_SAMPLES)
  {
    contention_handler_call();   /* only for the IRQ_SAMPLES counted interrupts */
  }

  uint32_t n = irq_count;
  if (n < IRQ_SAMPLES)
  {
    irq_samples[n] = ticks;
    if (phase_mode != 0U)
    {
      irq_phase[n] = (uint8_t)hw_phase;
    }
    if (n == 0U)
    {
      irq_first_cyc = now;
    }
    irq_last_cyc = now;
    irq_count = n + 1U;
  }
}

static void timer_init(void)
{
  RCC->APB1ENR1 |= RCC_APB1ENR1_TIM2EN;
  (void)RCC->APB1ENR1;

  TIM2->CR1 = 0U;
  TIM2->PSC = 0U;
  TIM2->ARR = IRQ_PERIOD - 1U;
  TIM2->EGR = TIM_EGR_UG;       /* load PSC/ARR */
  TIM2->SR = 0U;
  TIM2->DIER = TIM_DIER_UIE;

  NVIC_SetPriority(TIM2_IRQn, 0U);
  NVIC_ClearPendingIRQ(TIM2_IRQn);
  NVIC_EnableIRQ(TIM2_IRQn);
}

static void timer_start(void)
{
  irq_count = 0U;
  TIM2->CNT = 0U;
  TIM2->SR = 0U;
  NVIC_ClearPendingIRQ(TIM2_IRQn);
  TIM2->CR1 = TIM_CR1_CEN;
}

static void timer_stop(void)
{
  TIM2->CR1 = 0U;
  TIM2->SR = 0U;
  NVIC_ClearPendingIRQ(TIM2_IRQn);
}

/* Average cycles between recorded interrupts, measured with the DWT counter.
 * Should equal IRQ_PERIOD; confirms TIM2 ticks are CPU cycles. */
static uint32_t observed_period(void)
{
  return (irq_last_cyc - irq_first_cyc + (IRQ_SAMPLES - 1U) / 2U) / (IRQ_SAMPLES - 1U);
}

/*
 * Foreground computes 1 KB hardware MACs back to back while every interrupt
 * handler asks for a 16-byte one. Handler calls that land inside a foreground
 * call must get SECURE_ERR_BUSY; every MAC that is computed, in the handler or
 * the foreground, must match the software reference. Prints key=value counts.
 */
static void contention_run(void)
{
  uint8_t fg_ref[HMAC_SHA256_SIZE];
  uint32_t fg_runs = 0U;
  uint32_t fg_errors = 0U;

  if (SECURE_MAC_Compute(msg, IRQ_MSG_LEN, fg_ref) != SECURE_OK ||
      SECURE_MAC_Compute(msg, CONTENTION_MSG_LEN, contention_ref) != SECURE_OK)
  {
    uart_puts("# hw_contention aborted: reference MAC failed\n");
    return;
  }

  contention_ok = 0U;
  contention_busy = 0U;
  contention_errors = 0U;
  contention_mode = 1U;
  timer_start();
  while (irq_count < IRQ_SAMPLES)
  {
    if (SECURE_MAC_ComputeHw(msg, IRQ_MSG_LEN, mac) != SECURE_OK ||
        memcmp(mac, fg_ref, sizeof(fg_ref)) != 0)
    {
      fg_errors++;
    }
    fg_runs++;
  }
  timer_stop();
  contention_mode = 0U;

  uart_puts("# hw_contention_irqs=");
  uart_putu(IRQ_SAMPLES);
  uart_puts(" hw_contention_busy=");
  uart_putu(contention_busy);
  uart_puts(" hw_contention_ok=");
  uart_putu(contention_ok);
  uart_puts(" hw_contention_handler_errors=");
  uart_putu(contention_errors);
  uart_puts(" hw_contention_fg_runs=");
  uart_putu(fg_runs);
  uart_puts(" hw_contention_fg_errors=");
  uart_putu(fg_errors);
  uart_puts("\n");
}

/*
 * M6 diagnosis: rerun the hardware-HMAC scenario with the driver reporting its
 * phase, and print one row per phase (bytes column = phase id). Shows which
 * step of the driver holds off Non-Secure interrupts.
 */
static void hw_phase_run(void)
{
  static const char *const names[HASH_PHASE_COUNT] = {
    "irqph_none", "irqph_init", "irqph_key1", "irqph_key1_dcal", "irqph_key1_wait",
    "irqph_msg", "irqph_msg_dcal", "irqph_msg_wait", "irqph_key2", "irqph_key2_dcal",
    "irqph_final_wait", "irqph_digest"
  };

  hw_phase = HASH_PHASE_NONE;
  if (SECURE_Probe_SetHashPhaseMarker(&hw_phase) != SECURE_OK)
  {
    uart_puts("# hw_phase aborted: marker refused\n");
    return;
  }

  phase_mode = 1U;
  timer_start();
  while (irq_count < IRQ_SAMPLES)
  {
    (void)SECURE_MAC_ComputeHw(msg, IRQ_MSG_LEN, mac);
  }
  timer_stop();
  phase_mode = 0U;
  (void)SECURE_Probe_SetHashPhaseMarker(NULL);

  for (uint32_t p = 0U; p < HASH_PHASE_COUNT; p++)
  {
    uint32_t n = 0U;
    for (uint32_t i = 0U; i < IRQ_SAMPLES; i++)
    {
      if (irq_phase[i] == p)
      {
        phase_samples[n++] = irq_samples[i];
      }
    }
    if (n >= 2U)
    {
      bench_report(names[p], p, phase_samples, n);
    }
  }
}

void irq_latency_run(void)
{
  for (uint32_t i = 0U; i < IRQ_MSG_LEN; i++)
  {
    msg[i] = (uint8_t)i;
  }

  timer_init();
  __enable_irq();

  uart_puts("# M5: NS interrupt latency, cycles from timer event to handler\n");

  /* Idle NS loop. */
  timer_start();
  while (irq_count < IRQ_SAMPLES)
  {
  }
  timer_stop();
  uart_puts("# irq_period_cycles=");
  uart_putu(observed_period());
  uart_puts(" irq_period_expected=");
  uart_putu(IRQ_PERIOD);
  uart_puts("\n");
  bench_report("irq_idle_ns", 0U, irq_samples, IRQ_SAMPLES);

  /* HMAC in the Non-Secure world. */
  timer_start();
  while (irq_count < IRQ_SAMPLES)
  {
    (void)hmac_sha256(ns_key, sizeof(ns_key), msg, IRQ_MSG_LEN, mac);
  }
  timer_stop();
  bench_report("irq_hmac_ns", IRQ_MSG_LEN, irq_samples, IRQ_SAMPLES);

  /* HMAC in the Secure world: the interrupt preempts Secure code. */
  timer_start();
  while (irq_count < IRQ_SAMPLES)
  {
    (void)SECURE_MAC_Compute(msg, IRQ_MSG_LEN, mac);
  }
  timer_stop();
  bench_report("irq_hmac_s", IRQ_MSG_LEN, irq_samples, IRQ_SAMPLES);

  /* Back-to-back empty Secure calls: interrupts land in and around switches. */
  timer_start();
  while (irq_count < IRQ_SAMPLES)
  {
    SECURE_Nop();
  }
  timer_stop();
  bench_report("irq_nop_s", 0U, irq_samples, IRQ_SAMPLES);

  /* M6: HMAC on the HASH peripheral, driven from the Secure world. */
  timer_start();
  while (irq_count < IRQ_SAMPLES)
  {
    (void)SECURE_MAC_ComputeHw(msg, IRQ_MSG_LEN, mac);
  }
  timer_stop();
  bench_report("irq_hmac_hw_s", IRQ_MSG_LEN, irq_samples, IRQ_SAMPLES);

  hw_phase_run();

  contention_run();

  NVIC_DisableIRQ(TIM2_IRQn);
}
