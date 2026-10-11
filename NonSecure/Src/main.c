/*
 * Non-Secure world: M1 "Hello TrustZone".
 *
 * Calls into the Secure world through the NSC veneers and reports the results
 * on LPUART1 (PG7/PG8), which the NUCLEO-L552ZE-Q routes to the ST-LINK
 * virtual COM port at 115200 8N1.
 */
#include "stm32l5xx.h"
#include "secure_nsc.h"

#define UART_BAUD  115200UL

static void uart_init(void)
{
  RCC->AHB2ENR |= RCC_AHB2ENR_GPIOCEN | RCC_AHB2ENR_GPIOGEN;
  RCC->APB1ENR2 |= RCC_APB1ENR2_LPUART1EN;
  (void)RCC->APB1ENR2;

  /* PG7 = LPUART1_TX, PG8 = LPUART1_RX, both AF8. */
  GPIOG->MODER = (GPIOG->MODER & ~(GPIO_MODER_MODE7 | GPIO_MODER_MODE8))
               | (2U << GPIO_MODER_MODE7_Pos) | (2U << GPIO_MODER_MODE8_Pos);
  GPIOG->AFR[0] = (GPIOG->AFR[0] & ~GPIO_AFRL_AFSEL7) | (8U << GPIO_AFRL_AFSEL7_Pos);
  GPIOG->AFR[1] = (GPIOG->AFR[1] & ~GPIO_AFRH_AFSEL8) | (8U << GPIO_AFRH_AFSEL8_Pos);

  /* LPUART1 clocked from PCLK1 (reset default). LPUART: BRR = 256 * fck / baud. */
  LPUART1->CR1 = 0U;
  LPUART1->BRR = (uint32_t)(((uint64_t)SystemCoreClock * 256U + UART_BAUD / 2U) / UART_BAUD);
  LPUART1->CR1 = USART_CR1_TE | USART_CR1_UE;
}

static void uart_putc(char c)
{
  while ((LPUART1->ISR & USART_ISR_TXE_TXFNF) == 0U)
  {
  }
  LPUART1->TDR = (uint8_t)c;
}

static void uart_puts(const char *s)
{
  while (*s != '\0')
  {
    if (*s == '\n')
    {
      uart_putc('\r');
    }
    uart_putc(*s++);
  }
}

static void uart_putu(uint32_t v)
{
  char buf[11];
  int i = 0;

  do
  {
    buf[i++] = (char)('0' + (v % 10U));
    v /= 10U;
  } while (v != 0U);

  while (i > 0)
  {
    uart_putc(buf[--i]);
  }
}

static void led_init(void)
{
  /* PC7 = LD1 (green), push-pull output. */
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

  uart_puts("\n=== Hello TrustZone (Non-Secure world) ===\n");
  uart_puts("SystemCoreClock = ");
  uart_putu(SystemCoreClock);
  uart_puts(" Hz (read via NSC call)\n");

  uint32_t sum = SECURE_Add(2U, 3U);
  uart_puts("SECURE_Add(2, 3) = ");
  uart_putu(sum);
  uart_puts(sum == 5U ? "  [OK]\n" : "  [FAIL]\n");

  for (uint32_t i = 0U; i < 9U; i++)
  {
    (void)SECURE_Add(i, i);
  }
  uart_puts("SECURE_GetCallCount() = ");
  uart_putu(SECURE_GetCallCount());
  uart_puts(" (expected 10)\n");

  uart_puts("M1 done: NS -> S -> NS round trip works. Blinking LD1.\n");

  for (;;)
  {
    GPIOC->ODR ^= GPIO_ODR_OD7;
    delay(200000U);
  }
}
