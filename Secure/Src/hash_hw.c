/*
 * HMAC-SHA256 on the STM32L5 HASH peripheral (RM0438, HASH chapter).
 *
 * HMAC mode runs in three phases, each ended by setting STR.DCAL:
 *   1. key       (inner key, ipad applied by the peripheral)
 *   2. message
 *   3. key again (outer key, opad applied by the peripheral)
 * Keys longer than the 64-byte block need CR.LKEY so the peripheral hashes
 * them first. STR.NBLW gives the number of valid bits in the last word of
 * each phase (0 = all 32).
 *
 * DATATYPE = 8-bit: the peripheral byte-swaps each word, so words loaded
 * little-endian from memory are hashed in memory byte order.
 *
 * Message feed. When the CPU writes DIN, a write that hands a full block to the
 * hash core stalls the CPU on the bus for up to ~40 cycles, and a Non-Secure
 * interrupt cannot be taken until it completes (M6 phase diagnosis: all of
 * the extra worst-case latency was in the message DIN writes). The message is
 * therefore fed by DMA1 channel 1, so the DMA absorbs those stalls while the
 * CPU waits in an interruptible loop on the DMA status (never on HASH
 * registers, which a stalled DMA write would hold up). The short keys and
 * unaligned messages, which DMA word transfers cannot read, still go through
 * the CPU.
 *
 * The DMA channel is Secure (SECM) but its source is marked Non-Secure (SSEC
 * = 0): it can only read Non-Secure memory, whatever address it is given.
 * Word transfers read the whole last word; the up to 3 bytes past the message
 * end lie in the same aligned word, hence the same security region, and the
 * peripheral ignores them (NBLW).
 *
 * An earlier attempt kept the CPU feed and polled BUSY before each block; it
 * did not help, because the stall happens during the block hand-over itself
 * (results/bench_20261031_191738.csv).
 */
#include <arm_cmse.h>
#include <string.h>
#include "stm32l5xx.h"
#include "hash_hw.h"
#include "secure_nsc.h"

#define SHA256_BLOCK_SIZE   64U
#define HASH_TIMEOUT_LOOPS  1000000U
#define HASH_DMA_REQ_ID     92U     /* DMAMUX1 request HASH_IN (ST HAL DMA_REQUEST_HASH_IN) */

/* M6 latency diagnosis: when set, the driver writes its current phase
 * (HASH_PHASE_*) here so a Non-Secure interrupt handler can see where it
 * landed. NULL in normal operation. */
static volatile uint32_t *phase_marker;

static inline void mark(uint32_t phase)
{
  if (phase_marker != NULL)
  {
    *phase_marker = phase;
  }
}

void hash_hw_set_phase_marker(volatile uint32_t *marker)
{
  phase_marker = marker;
}

void hash_hw_init(void)
{
  RCC->AHB2ENR |= RCC_AHB2ENR_HASHEN;
  (void)RCC->AHB2ENR;

  RCC->AHB1ENR |= RCC_AHB1ENR_DMA1EN | RCC_AHB1ENR_DMAMUX1EN;
  (void)RCC->AHB1ENR;
}

/* Feeds len bytes to DIN as 32-bit words. The tail word is assembled byte by
 * byte so nothing past buf[len - 1] is read (buf may be a caller's buffer whose
 * end was bounds-checked exactly). */
static void hash_write(const uint8_t *buf, size_t len)
{
  size_t i = 0U;

  for (; i + 4U <= len; i += 4U)
  {
    uint32_t w;
    memcpy(&w, &buf[i], sizeof(w));     /* buf may be unaligned */
    HASH->DIN = w;
  }
  if (i < len)
  {
    uint32_t w = 0U;
    for (size_t k = 0U; i + k < len; k++)
    {
      w |= (uint32_t)buf[i + k] << (8U * k);
    }
    HASH->DIN = w;
  }
}

static int wait_flag_clear(uint32_t flag)
{
  for (uint32_t n = 0U; n < HASH_TIMEOUT_LOOPS; n++)
  {
    if ((HASH->SR & flag) == 0U)
    {
      return 0;
    }
  }
  return -1;
}

static int wait_flag_set(uint32_t flag)
{
  for (uint32_t n = 0U; n < HASH_TIMEOUT_LOOPS; n++)
  {
    if ((HASH->SR & flag) != 0U)
    {
      return 0;
    }
  }
  return -1;
}

/* One HMAC phase: NBLW, data, DCAL. */
static void hash_phase(const uint8_t *buf, size_t len, uint32_t data_phase, uint32_t dcal_phase)
{
  mark(data_phase);
  HASH->STR = (uint32_t)((len % 4U) * 8U) << HASH_STR_NBLW_Pos;
  hash_write(buf, len);
  mark(dcal_phase);
  HASH->STR |= HASH_STR_DCAL;
}

/* Feeds a 4-byte-aligned message to DIN with DMA1 channel 1. With MDMAT = 0 the
 * peripheral starts the digest by itself after the last word (no DCAL). */
static int hash_dma_message(const uint8_t *msg, size_t len)
{
  DMA_Channel_TypeDef *ch = DMA1_Channel1;

  ch->CCR = 0U;
  DMA1->IFCR = DMA_IFCR_CGIF1;
  ch->CPAR = (uint32_t)&HASH->DIN;
  ch->CM0AR = (uint32_t)msg;
  ch->CNDTR = (uint32_t)((len + 3U) / 4U);
  ch->CCR = DMA_CCR_SECM | DMA_CCR_DSEC          /* Secure channel, Secure dest (HASH) */
          | DMA_CCR_DIR | DMA_CCR_MINC           /* memory -> peripheral */
          | DMA_CCR_PSIZE_1 | DMA_CCR_MSIZE_1;   /* 32-bit; SSEC = 0: NS source */
  /* DMAMUX channel 0 (-> DMA1 ch1) takes its security from the DMA channel, so
   * route the request only once SECM is set; a Secure write before that is
   * ignored (found on the board: DMAMUX CCR read back 0). */
  DMAMUX1_Channel0->CCR = HASH_DMA_REQ_ID << DMAMUX_CxCR_DMAREQ_ID_Pos;
  ch->CCR |= DMA_CCR_EN;
  HASH->CR |= HASH_CR_DMAE;

  int ret = -1;
  for (uint32_t n = 0U; n < HASH_TIMEOUT_LOOPS; n++)
  {
    uint32_t isr = DMA1->ISR;
    if ((isr & DMA_ISR_TEIF1) != 0U)
    {
      break;
    }
    if ((isr & DMA_ISR_TCIF1) != 0U)
    {
      ret = 0;
      break;
    }
  }

  ch->CCR = 0U;
  DMA1->IFCR = DMA_IFCR_CGIF1;
  HASH->CR &= ~HASH_CR_DMAE;
  return ret;
}

int hash_hw_hmac_sha256(const uint8_t *key, size_t key_len,
                        const uint8_t *msg, size_t msg_len,
                        uint8_t out[HASH_HW_MAC_SIZE])
{
  uint32_t cr = HASH_CR_ALGO_1 | HASH_CR_ALGO_0   /* SHA-256 */
              | HASH_CR_MODE                      /* HMAC */
              | HASH_CR_DATATYPE_1;               /* 8-bit data */
  if (key_len > SHA256_BLOCK_SIZE)
  {
    cr |= HASH_CR_LKEY;
  }
  mark(HASH_PHASE_INIT);
  HASH->CR = cr;
  HASH->CR = cr | HASH_CR_INIT;                   /* start a new digest */

  hash_phase(key, key_len, HASH_PHASE_KEY1, HASH_PHASE_KEY1_DCAL);
  mark(HASH_PHASE_KEY1_WAIT);
  if (wait_flag_clear(HASH_SR_BUSY) != 0)
  {
    return -1;
  }

  /* DMA only for aligned, Non-Secure messages: its source is NS-only (SSEC = 0),
   * so Secure buffers (e.g. the self-test vectors) go through the CPU. */
  if (msg_len != 0U && ((uintptr_t)msg % 4U) == 0U &&
      cmse_TT((void *)msg).flags.secure == 0U &&
      cmse_TT((void *)&msg[msg_len - 1U]).flags.secure == 0U)
  {
    mark(HASH_PHASE_MSG);
    HASH->STR = (uint32_t)((msg_len % 4U) * 8U) << HASH_STR_NBLW_Pos;
    if (hash_dma_message(msg, msg_len) != 0)
    {
      return -1;
    }
  }
  else
  {
    hash_phase(msg, msg_len, HASH_PHASE_MSG, HASH_PHASE_MSG_DCAL);
  }
  mark(HASH_PHASE_MSG_WAIT);
  if (wait_flag_clear(HASH_SR_BUSY) != 0)
  {
    return -1;
  }

  hash_phase(key, key_len, HASH_PHASE_KEY2, HASH_PHASE_KEY2_DCAL);
  mark(HASH_PHASE_FINAL_WAIT);
  if (wait_flag_set(HASH_SR_DCIS) != 0)
  {
    return -1;
  }

  mark(HASH_PHASE_DIGEST);
  for (uint32_t i = 0U; i < HASH_HW_MAC_SIZE / 4U; i++)
  {
    uint32_t w = __REV(HASH_DIGEST->HR[i]);     /* digest words are big-endian */
    memcpy(&out[4U * i], &w, sizeof(w));
  }
  mark(HASH_PHASE_NONE);
  return 0;
}
