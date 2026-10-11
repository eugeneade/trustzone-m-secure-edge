#include "stm32l5xx.h"
#include "uart.h"

#define UART_BAUD  115200UL

void uart_init(void)
{
  RCC->AHB2ENR |= RCC_AHB2ENR_GPIOGEN;
  RCC->APB1ENR2 |= RCC_APB1ENR2_LPUART1EN;
  (void)RCC->APB1ENR2;

  /* PG7 = LPUART1_TX, PG8 = LPUART1_RX, both AF8. */
  GPIOG->MODER = (GPIOG->MODER & ~(GPIO_MODER_MODE7 | GPIO_MODER_MODE8))
               | (2U << GPIO_MODER_MODE7_Pos) | (2U << GPIO_MODER_MODE8_Pos);
  GPIOG->AFR[0] = (GPIOG->AFR[0] & ~GPIO_AFRL_AFSEL7) | (8U << GPIO_AFRL_AFSEL7_Pos);
  GPIOG->AFR[1] = (GPIOG->AFR[1] & ~GPIO_AFRH_AFSEL8) | (8U << GPIO_AFRH_AFSEL8_Pos);

  /* LPUART1 clocked from PCLK1 = SystemCoreClock (APB1 /1). BRR = 256 * fck / baud. */
  LPUART1->CR1 = 0U;
  LPUART1->BRR = (uint32_t)(((uint64_t)SystemCoreClock * 256U + UART_BAUD / 2U) / UART_BAUD);
  LPUART1->CR1 = USART_CR1_TE | USART_CR1_UE;
}

void uart_putc(char c)
{
  while ((LPUART1->ISR & USART_ISR_TXE_TXFNF) == 0U)
  {
  }
  LPUART1->TDR = (uint8_t)c;
}

void uart_puts(const char *s)
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

void uart_putu(uint32_t v)
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

void uart_puthex(const uint8_t *p, uint32_t len)
{
  static const char hex[] = "0123456789abcdef";

  for (uint32_t i = 0U; i < len; i++)
  {
    uart_putc(hex[p[i] >> 4]);
    uart_putc(hex[p[i] & 0xFU]);
  }
}
