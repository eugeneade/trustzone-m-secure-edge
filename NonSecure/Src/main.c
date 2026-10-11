/*
 * Non-Secure world: application side of the Secure crypto service.
 *
 * Exercises the Secure world through the NSC veneers (M1 round trip, M2 MAC
 * service and pointer validation), then runs the M3 benchmark. Results go to
 * the ST-LINK virtual COM port (see uart.h).
 */
#include <stddef.h>
#include "stm32l5xx.h"
#include "secure_nsc.h"
#include "bench.h"
#include "uart.h"

static uint32_t failures;

static void check(const char *what, int ok)
{
  uart_puts(ok ? "  [OK]   " : "  [FAIL] ");
  uart_puts(what);
  uart_puts("\n");
  if (!ok)
  {
    failures++;
  }
}

static void led_init(void)
{
  /* PC7 = LD1 (green), push-pull output. */
  RCC->AHB2ENR |= RCC_AHB2ENR_GPIOCEN;
  (void)RCC->AHB2ENR;
  GPIOC->MODER = (GPIOC->MODER & ~GPIO_MODER_MODE7) | (1U << GPIO_MODER_MODE7_Pos);
}

static void delay(volatile uint32_t n)
{
  while (n-- != 0U)
  {
  }
}

int main(void)
{
  SystemCoreClockUpdate();   /* NSC call: SECURE_SystemCoreClockUpdate() */
  uart_init();
  led_init();

  uart_puts("\n=== TrustZone Secure Edge (Non-Secure world) ===\n");
  uart_puts("SystemCoreClock = ");
  uart_putu(SystemCoreClock);
  uart_puts(" Hz (read via NSC call)\n");

  /* ---- M1: basic NSC round trip ---- */
  uart_puts("\nM1: NS -> S -> NS calls\n");
  check("SECURE_Add(2, 3) == 5", SECURE_Add(2U, 3U) == 5U);
  for (uint32_t i = 0U; i < 9U; i++)
  {
    (void)SECURE_Add(i, i);
  }
  check("SECURE_GetCallCount() == 10", SECURE_GetCallCount() == 10U);

  /* ---- M2: Secure crypto service ---- */
  uart_puts("\nM2: HMAC-SHA256 with device key held in the Secure world\n");
  check("RFC 4231 self-test (TC1, TC2, TC6)", SECURE_CryptoSelfTest() == SECURE_OK);

  uint8_t msg[] = "temp=21.5C;seq=1";
  const uint32_t msg_len = sizeof(msg) - 1U;
  uint8_t mac[SECURE_MAC_SIZE];

  check("MAC_Compute(msg)", SECURE_MAC_Compute(msg, msg_len, mac) == SECURE_OK);
  uart_puts("         msg = \"");
  uart_puts((const char *)msg);
  uart_puts("\"\n         mac = ");
  uart_puthex(mac, sizeof(mac));
  uart_puts("\n");

  check("MAC_Verify(msg, mac) accepts", SECURE_MAC_Verify(msg, msg_len, mac) == SECURE_OK);

  msg[msg_len - 1U] = '2';   /* replay with a modified sequence number */
  check("MAC_Verify(tampered msg) rejects", SECURE_MAC_Verify(msg, msg_len, mac) == SECURE_ERR_MAC);
  msg[msg_len - 1U] = '1';

  mac[0] ^= 0x01U;
  check("MAC_Verify(tampered mac) rejects", SECURE_MAC_Verify(msg, msg_len, mac) == SECURE_ERR_MAC);
  mac[0] ^= 0x01U;

  /* Confused-deputy attempts: ask the Secure world to read or write Secure memory. */
  check("MAC_Compute(msg in Secure flash) refused",
        SECURE_MAC_Compute((const uint8_t *)0x0C000000UL, 64U, mac) == SECURE_ERR_PARAM);
  check("MAC_Compute(mac out to Secure SRAM) refused",
        SECURE_MAC_Compute(msg, msg_len, (uint8_t *)0x30000000UL) == SECURE_ERR_PARAM);
  check("MAC_Compute(NULL mac) refused",
        SECURE_MAC_Compute(msg, msg_len, NULL) == SECURE_ERR_PARAM);

  uart_puts(failures == 0U ? "\nAll checks passed.\n" : "\nSome checks FAILED.\n");

  /* ---- M3: latency measurements ---- */
  bench_run();
  uart_puts("Benchmark done. Blinking LD1.\n");

#ifdef ISOLATION_TEST
  /* Direct NS read of Secure flash (where the device key lives). The SAU/IDAU
   * blocks it and the Secure SecureFault handler reports it on the UART. */
  uart_puts("\nISOLATION_TEST: NS reading Secure flash at 0x0C000000 ...\n");
  volatile uint32_t leaked = *(volatile const uint32_t *)0x0C000000UL;
  uart_puts("  [FAIL] read succeeded, value = ");
  uart_putu(leaked);
  uart_puts("\n");
#endif

  for (;;)
  {
    GPIOC->ODR ^= GPIO_ODR_OD7;
    delay(200000U);
  }
}
