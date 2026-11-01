/*
 * Secure crypto service (M2): HMAC-SHA256 with a device key that never
 * leaves the Secure world.
 *
 * The HMAC itself is in Common/Src/hmac_sha256.c (shared with the NS
 * baseline used for M3); SECURE_CryptoSelfTest() checks it against the
 * RFC 4231 test vectors.
 *
 * Every NSC entry point validates Non-Secure pointers with
 * cmse_check_address_range() before touching them; otherwise the NS app
 * could ask the Secure world to read or overwrite Secure memory on its
 * behalf (confused deputy).
 */
#include <arm_cmse.h>
#include <stddef.h>
#include <string.h>
#include "stm32l5xx.h"
#include "hash_hw.h"
#include "hmac_sha256.h"
#include "mbedtls/platform_util.h"
#include "secure_nsc.h"

#define CMSE_NS_ENTRY  __attribute((cmse_nonsecure_entry))

/*
 * Demo device key, stored in Secure flash. A production device would
 * provision a per-device key (e.g. into Secure flash or OTP at manufacture)
 * instead of compiling one in.
 */
static const uint8_t device_key[32] = {
  0x6b, 0x1f, 0x93, 0x0e, 0xc4, 0x57, 0x28, 0xa1, 0x3d, 0x80, 0xf2, 0x5c, 0x19, 0xe6, 0x74, 0xbb,
  0x02, 0x9a, 0x4f, 0xd8, 0x61, 0x37, 0xce, 0x85, 0xe0, 0x2b, 0x7d, 0x46, 0xa9, 0x13, 0xf5, 0x6c
};

/* Returns 0 iff equal; run time does not depend on where the buffers differ. */
static uint32_t ct_compare(const uint8_t *a, const volatile uint8_t *b, size_t len)
{
  uint32_t diff = 0U;

  for (size_t i = 0U; i < len; i++)
  {
    diff |= (uint32_t)(a[i] ^ b[i]);
  }
  return diff;
}

/*
 * Erase a 4-byte-aligned Secure buffer one word at a time (len a multiple of 4).
 * Volatile stores cannot be optimised away. M4 found the generic
 * mbedtls_platform_zeroize -> newlib-nano memset path clears one byte per
 * loop iteration, which made it the largest cost of SECURE_MAC_Compute.
 */
static void zeroize_words(void *buf, size_t len)
{
  volatile uint32_t *w = (volatile uint32_t *)buf;

  for (size_t i = 0U; i < len / 4U; i++)
  {
    w[i] = 0U;
  }
  __asm volatile ("" ::: "memory");
}

/* True if [p, p+len) is entirely Non-Secure and accessible with the given MPU flags. */
static int ns_buffer_ok(const void *p, uint32_t len, int mpu_flags)
{
  if (len == 0U)
  {
    return 1;
  }
  if (p == NULL)
  {
    return 0;
  }
  return cmse_check_address_range((void *)p, len, CMSE_NONSECURE | mpu_flags) != NULL;
}

/*
 * The HASH peripheral holds one computation at a time. A Non-Secure interrupt
 * handler can call into the Secure world while an earlier call is suspended
 * mid-computation; that nested call must not touch the peripheral. On this
 * single core a nested call runs to completion before the outer one resumes,
 * so a plain flag is enough: the outer and nested calls never both proceed.
 */
static volatile uint32_t hash_hw_busy;

static int hash_hw_acquire(void)
{
  if (hash_hw_busy != 0U)
  {
    return 0;
  }
  hash_hw_busy = 1U;
  return 1;
}

static void hash_hw_release(void)
{
  hash_hw_busy = 0U;
}

typedef int (*hmac_fn_t)(const uint8_t *key, size_t key_len,
                         const uint8_t *msg, size_t msg_len, uint8_t out[SECURE_MAC_SIZE]);

/* RFC 4231 test cases 1, 2 and 6 (6 exercises the hashed long-key path). */
static secure_status_t hmac_kat(hmac_fn_t hmac)
{
  static const uint8_t tc1_data[] = "Hi There";
  static const uint8_t tc1_mac[SECURE_MAC_SIZE] = {
    0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
    0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7
  };
  static const uint8_t tc2_key[] = "Jefe";
  static const uint8_t tc2_data[] = "what do ya want for nothing?";
  static const uint8_t tc2_mac[SECURE_MAC_SIZE] = {
    0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7,
    0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43
  };
  static const uint8_t tc6_data[] = "Test Using Larger Than Block-Size Key - Hash Key First";
  static const uint8_t tc6_mac[SECURE_MAC_SIZE] = {
    0x60, 0xe4, 0x31, 0x59, 0x1e, 0xe0, 0xb6, 0x7f, 0x0d, 0x8a, 0x26, 0xaa, 0xcb, 0xf5, 0xb7, 0x7f,
    0x8e, 0x0b, 0xc6, 0x21, 0x37, 0x28, 0xc5, 0x14, 0x05, 0x46, 0x04, 0x0f, 0x0e, 0xe3, 0x7f, 0x54
  };

  uint8_t key[131];
  uint8_t mac[SECURE_MAC_SIZE] __attribute__((aligned(4)));
  uint32_t fail = 0U;

  memset(key, 0x0b, 20);
  fail |= (uint32_t)hmac(key, 20, tc1_data, sizeof(tc1_data) - 1U, mac);
  fail |= ct_compare(mac, tc1_mac, sizeof(mac));

  fail |= (uint32_t)hmac(tc2_key, sizeof(tc2_key) - 1U, tc2_data, sizeof(tc2_data) - 1U, mac);
  fail |= ct_compare(mac, tc2_mac, sizeof(mac));

  memset(key, 0xaa, sizeof(key));
  fail |= (uint32_t)hmac(key, sizeof(key), tc6_data, sizeof(tc6_data) - 1U, mac);
  fail |= ct_compare(mac, tc6_mac, sizeof(mac));

  zeroize_words(mac, sizeof(mac));
  return (fail == 0U) ? SECURE_OK : SECURE_ERR_SELFTEST;
}

/* ---------------------------- NSC entry points ---------------------------- */

CMSE_NS_ENTRY secure_status_t SECURE_CryptoSelfTest(void)
{
  return hmac_kat(hmac_sha256);
}

CMSE_NS_ENTRY secure_status_t SECURE_CryptoSelfTestHw(void)
{
  if (!hash_hw_acquire())
  {
    return SECURE_ERR_BUSY;
  }
  secure_status_t status = hmac_kat(hash_hw_hmac_sha256);
  hash_hw_release();
  return status;
}

CMSE_NS_ENTRY secure_status_t SECURE_MAC_Compute(const uint8_t *msg, uint32_t len,
                                                 uint8_t mac[SECURE_MAC_SIZE])
{
  uint8_t tag[SECURE_MAC_SIZE] __attribute__((aligned(4)));

  if (!ns_buffer_ok(msg, len, CMSE_MPU_READ) ||
      mac == NULL || !ns_buffer_ok(mac, SECURE_MAC_SIZE, CMSE_MPU_READWRITE))
  {
    return SECURE_ERR_PARAM;
  }

  /* Compute into Secure memory, then copy out, so a failure never leaves a partial tag. */
  if (hmac_sha256(device_key, sizeof(device_key), msg, len, tag) != 0)
  {
    zeroize_words(tag, sizeof(tag));
    return SECURE_ERR_INTERNAL;
  }
  memcpy(mac, tag, sizeof(tag));
  zeroize_words(tag, sizeof(tag));
  return SECURE_OK;
}

CMSE_NS_ENTRY secure_status_t SECURE_MAC_Verify(const uint8_t *msg, uint32_t len,
                                                const uint8_t mac[SECURE_MAC_SIZE])
{
  uint8_t tag[SECURE_MAC_SIZE] __attribute__((aligned(4)));
  secure_status_t status;

  if (!ns_buffer_ok(msg, len, CMSE_MPU_READ) ||
      mac == NULL || !ns_buffer_ok(mac, SECURE_MAC_SIZE, CMSE_MPU_READ))
  {
    return SECURE_ERR_PARAM;
  }

  if (hmac_sha256(device_key, sizeof(device_key), msg, len, tag) != 0)
  {
    status = SECURE_ERR_INTERNAL;
  }
  else
  {
    status = (ct_compare(tag, mac, sizeof(tag)) == 0U) ? SECURE_OK : SECURE_ERR_MAC;
  }
  zeroize_words(tag, sizeof(tag));
  return status;
}

/* M6: same contract as SECURE_MAC_Compute, computed by the HASH peripheral. */
CMSE_NS_ENTRY secure_status_t SECURE_MAC_ComputeHw(const uint8_t *msg, uint32_t len,
                                                   uint8_t mac[SECURE_MAC_SIZE])
{
  uint8_t tag[SECURE_MAC_SIZE] __attribute__((aligned(4)));

  if (!ns_buffer_ok(msg, len, CMSE_MPU_READ) ||
      mac == NULL || !ns_buffer_ok(mac, SECURE_MAC_SIZE, CMSE_MPU_READWRITE))
  {
    return SECURE_ERR_PARAM;
  }
  if (!hash_hw_acquire())
  {
    return SECURE_ERR_BUSY;
  }

  int ret = hash_hw_hmac_sha256(device_key, sizeof(device_key), msg, len, tag);
  hash_hw_release();

  if (ret != 0)
  {
    zeroize_words(tag, sizeof(tag));
    return SECURE_ERR_INTERNAL;
  }
  memcpy(mac, tag, sizeof(tag));
  zeroize_words(tag, sizeof(tag));
  return SECURE_OK;
}

/* ------------------------- M4 measurement probes -------------------------- */
/*
 * Each probe performs one more step of SECURE_MAC_Compute than the previous
 * one, in the same order, so the difference between consecutive probes is the
 * cost of that step. Measurement-only entry points: a production build would
 * leave them out.
 */

CMSE_NS_ENTRY secure_status_t SECURE_Probe_Args(const uint8_t *msg, uint32_t len,
                                                uint8_t mac[SECURE_MAC_SIZE])
{
  (void)msg;
  (void)len;
  (void)mac;
  return SECURE_OK;
}

CMSE_NS_ENTRY secure_status_t SECURE_Probe_Checks(const uint8_t *msg, uint32_t len,
                                                  uint8_t mac[SECURE_MAC_SIZE])
{
  if (!ns_buffer_ok(msg, len, CMSE_MPU_READ) ||
      mac == NULL || !ns_buffer_ok(mac, SECURE_MAC_SIZE, CMSE_MPU_READWRITE))
  {
    return SECURE_ERR_PARAM;
  }
  return SECURE_OK;
}

/* Cycles spent in hmac_sha256() alone, timed inside the Secure world. */
CMSE_NS_ENTRY uint32_t SECURE_Probe_HmacCycles(const uint8_t *msg, uint32_t len,
                                               uint8_t mac[SECURE_MAC_SIZE])
{
  uint8_t tag[SECURE_MAC_SIZE] __attribute__((aligned(4)));

  if (!ns_buffer_ok(msg, len, CMSE_MPU_READ) ||
      mac == NULL || !ns_buffer_ok(mac, SECURE_MAC_SIZE, CMSE_MPU_READWRITE))
  {
    return 0U;
  }

  uint32_t t0 = DWT->CYCCNT;
  int ret = hmac_sha256(device_key, sizeof(device_key), msg, len, tag);
  uint32_t t1 = DWT->CYCCNT;

  zeroize_words(tag, sizeof(tag));
  return (ret == 0) ? (t1 - t0) : 0U;
}

/*
 * SECURE_MAC_Compute with each step timed inside the Secure world, so the
 * steps add up exactly (no cross-world call overhead in any of them).
 * steps[] receives cycles for: pointer checks, HMAC, copy-out, zeroize, and
 * (for comparison only) the previous mbedtls_platform_zeroize on a same-size
 * buffer.
 */
CMSE_NS_ENTRY secure_status_t SECURE_Probe_MacSteps(const uint8_t *msg, uint32_t len,
                                                    uint8_t mac[SECURE_MAC_SIZE],
                                                    uint32_t steps[SECURE_PROBE_STEPS])
{
  uint8_t tag[SECURE_MAC_SIZE] __attribute__((aligned(4)));
  uint8_t old[SECURE_MAC_SIZE] __attribute__((aligned(4)));

  if (steps == NULL ||
      !ns_buffer_ok(steps, SECURE_PROBE_STEPS * sizeof(uint32_t), CMSE_MPU_READWRITE))
  {
    return SECURE_ERR_PARAM;
  }

  uint32_t t0 = DWT->CYCCNT;
  if (!ns_buffer_ok(msg, len, CMSE_MPU_READ) ||
      mac == NULL || !ns_buffer_ok(mac, SECURE_MAC_SIZE, CMSE_MPU_READWRITE))
  {
    return SECURE_ERR_PARAM;
  }
  uint32_t t1 = DWT->CYCCNT;
  int ret = hmac_sha256(device_key, sizeof(device_key), msg, len, tag);
  uint32_t t2 = DWT->CYCCNT;
  memcpy(mac, tag, sizeof(tag));
  uint32_t t3 = DWT->CYCCNT;
  zeroize_words(tag, sizeof(tag));
  uint32_t t4 = DWT->CYCCNT;
  mbedtls_platform_zeroize(old, sizeof(old));
  uint32_t t5 = DWT->CYCCNT;

  steps[0] = t1 - t0;
  steps[1] = t2 - t1;
  steps[2] = t3 - t2;
  steps[3] = t4 - t3;
  steps[4] = t5 - t4;
  return (ret == 0) ? SECURE_OK : SECURE_ERR_INTERNAL;
}

/* M6: cycles of hash_hw_hmac_sha256() alone, timed inside the Secure world
 * (0 on error or if the peripheral is busy). */
CMSE_NS_ENTRY uint32_t SECURE_Probe_HwHmacCycles(const uint8_t *msg, uint32_t len,
                                                 uint8_t mac[SECURE_MAC_SIZE])
{
  uint8_t tag[SECURE_MAC_SIZE] __attribute__((aligned(4)));

  if (!ns_buffer_ok(msg, len, CMSE_MPU_READ) ||
      mac == NULL || !ns_buffer_ok(mac, SECURE_MAC_SIZE, CMSE_MPU_READWRITE) ||
      !hash_hw_acquire())
  {
    return 0U;
  }

  uint32_t t0 = DWT->CYCCNT;
  int ret = hash_hw_hmac_sha256(device_key, sizeof(device_key), msg, len, tag);
  uint32_t t1 = DWT->CYCCNT;

  hash_hw_release();
  zeroize_words(tag, sizeof(tag));
  return (ret == 0) ? (t1 - t0) : 0U;
}

/* M6 latency diagnosis: let the NS app watch which driver phase an interrupt
 * lands in. The marker must be a Non-Secure, writable word (or NULL). */
CMSE_NS_ENTRY secure_status_t SECURE_Probe_SetHashPhaseMarker(volatile uint32_t *marker)
{
  if (marker != NULL &&
      !ns_buffer_ok((const void *)marker, sizeof(*marker), CMSE_MPU_READWRITE))
  {
    return SECURE_ERR_PARAM;
  }
  hash_hw_set_phase_marker(marker);
  return SECURE_OK;
}
