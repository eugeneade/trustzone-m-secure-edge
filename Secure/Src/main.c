/*
 * Secure world: configure the TrustZone partition and boot the Non-Secure app.
 *
 * Memory map (matches ST's STM32L552xE_FLASH_s/_ns.ld and partition_stm32l552xx.h):
 *   Secure code      0x0C000000 - 0x0C03DFFF  (flash bank 1)
 *   NSC veneers      0x0C03E000 - 0x0C03FFFF
 *   Non-Secure code  0x08040000 - 0x0807FFFF  (flash bank 2)
 *   Secure SRAM      0x30000000 - 0x30017FFF  (SRAM1 lower 96 KB)
 *   Non-Secure SRAM  0x20018000 - 0x2003FFFF  (SRAM1 upper 96 KB + SRAM2)
 *
 * SAU regions are set by TZ_SAU_Setup() in SystemInit(). This file handles the
 * GTZC (SRAM block-based security) and GPIO pin security, which the SAU does
 * not cover.
 */
#include <arm_cmse.h>
#include "stm32l5xx.h"
#include "secure_nsc.h"

/* Same definition as ST's system_stm32l5xx_s.c (not exported in a header). */
#define CMSE_NS_ENTRY     __attribute((cmse_nonsecure_entry))

#define NS_VTOR_BASE      0x08040000UL

/* GTZC MPCBB: one VCTR register covers 32 blocks x 256 B = 8 KB of SRAM. */
#define MPCBB_BLOCK_REG_SIZE  (8U * 1024U)
#define SRAM1_NS_OFFSET       (96U * 1024U)

typedef void (*ns_funcptr_t)(void) __attribute__((cmse_nonsecure_call));

static volatile uint32_t secure_call_count;

static void gtzc_sram_setup(void)
{
  RCC->AHB1ENR |= RCC_AHB1ENR_GTZCEN;
  (void)RCC->AHB1ENR;

  /* SRAM1 upper 96 KB -> Non-Secure. */
  for (uint32_t i = SRAM1_NS_OFFSET / MPCBB_BLOCK_REG_SIZE; i < 24U; i++)
  {
    GTZC_MPCBB1->VCTR[i] = 0U;
  }

  /* SRAM2 (64 KB) -> Non-Secure. */
  for (uint32_t i = 0U; i < (64U * 1024U) / MPCBB_BLOCK_REG_SIZE; i++)
  {
    GTZC_MPCBB2->VCTR[i] = 0U;
  }
}

static void board_io_setup(void)
{
  /* PG2..PG15 are powered from VDDIO2, which must be declared valid. */
  RCC->APB1ENR1 |= RCC_APB1ENR1_PWREN;
  (void)RCC->APB1ENR1;
  PWR->CR2 |= PWR_CR2_IOSV;

  RCC->AHB2ENR |= RCC_AHB2ENR_GPIOCEN | RCC_AHB2ENR_GPIOGEN;
  (void)RCC->AHB2ENR;

  /* With TZEN=1 every GPIO pin resets as Secure. Release the pins the NS app uses:
   *   PC7      LD1 (green LED)
   *   PG7/PG8  LPUART1 TX/RX -> ST-LINK virtual COM port */
  GPIOC->SECCFGR &= ~GPIO_SECCFGR_SEC7;
  GPIOG->SECCFGR &= ~(GPIO_SECCFGR_SEC7 | GPIO_SECCFGR_SEC8);
}

/* ------------------------------ Fault report ------------------------------ */

/* Minimal polled output on LPUART1, which the NS app owns and has already
 * initialised by the time any fault can occur. Secure code reaches it through
 * its Non-Secure alias. */
static void fault_puts(const char *s)
{
  while (*s != '\0')
  {
    while ((LPUART1_NS->ISR & USART_ISR_TXE_TXFNF) == 0U)
    {
    }
    LPUART1_NS->TDR = (uint8_t)*s++;
  }
}

static void fault_puthex(uint32_t v)
{
  static const char hex[] = "0123456789ABCDEF";
  char buf[11] = "0x";

  for (int i = 0; i < 8; i++)
  {
    buf[2 + i] = hex[(v >> (28 - 4 * i)) & 0xFU];
  }
  buf[10] = '\0';
  fault_puts(buf);
}

static void fault_report(const char *name)
{
  fault_puts("\r\n*** Secure world caught ");
  fault_puts(name);
  fault_puts(": SFSR=");
  fault_puthex(SAU->SFSR);
  fault_puts(" SFAR=");
  fault_puthex(SAU->SFAR);
  fault_puts(" HFSR=");
  fault_puthex(SCB->HFSR);
  fault_puts("\r\n*** Non-Secure access to Secure memory was blocked. Halting.\r\n");
  for (;;)
  {
  }
}

void SecureFault_Handler(void)
{
  fault_report("SecureFault");
}

void HardFault_Handler(void)
{
  fault_report("HardFault");
}

/* ------------------------------- Boot path -------------------------------- */

static void nonsecure_boot(void)
{
  const uint32_t *ns_vectors = (const uint32_t *)NS_VTOR_BASE;

  SCB_NS->VTOR = NS_VTOR_BASE;
  __TZ_set_MSP_NS(ns_vectors[0]);

  ns_funcptr_t ns_reset = (ns_funcptr_t)cmse_nsfptr_create(ns_vectors[1]);
  ns_reset();
}

int main(void)
{
  /* Report NS -> S violations as SecureFault rather than escalated HardFault. */
  SCB->SHCSR |= SCB_SHCSR_SECUREFAULTENA_Msk;

  gtzc_sram_setup();
  board_io_setup();
  nonsecure_boot();

  /* Not reached: the NS app never returns. */
  for (;;)
  {
  }
}

/* ---------------------------- NSC entry points ---------------------------- */

CMSE_NS_ENTRY uint32_t SECURE_Add(uint32_t a, uint32_t b)
{
  secure_call_count++;
  return a + b;
}

CMSE_NS_ENTRY uint32_t SECURE_GetCallCount(void)
{
  return secure_call_count;
}
