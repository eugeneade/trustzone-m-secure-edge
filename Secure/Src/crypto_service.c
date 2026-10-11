/*
 * Secure crypto service (M2): HMAC-SHA256 with a device key that never
 * leaves the Secure world.
 *
 * HMAC (RFC 2104) is built on mbedTLS SHA-256 rather than mbedtls_md_hmac_*,
 * which would need a heap in the Secure image. Correctness is checked against
 * the RFC 4231 test vectors by SECURE_CryptoSelfTest().
 *
 * Every NSC entry point validates Non-Secure pointers with
 * cmse_check_address_range() before touching them; otherwise the NS app
 * could ask the Secure world to read or overwrite Secure memory on its
 * behalf (confused deputy).
 */
#include <arm_cmse.h>
#include <stddef.h>
#include <string.h>
#include "mbedtls/sha256.h"
#include "mbedtls/platform_util.h"
#include "secure_nsc.h"

#define CMSE_NS_ENTRY  __attribute((cmse_nonsecure_entry))

#define SHA256_BLOCK_SIZE  64U

/*
 * Demo device key, stored in Secure flash. A production device would
 * provision a per-device key (e.g. into Secure flash or OTP at manufacture)
 * instead of compiling one in.
 */
static const uint8_t device_key[32] = {
  0x6b, 0x1f, 0x93, 0x0e, 0xc4, 0x57, 0x28, 0xa1, 0x3d, 0x80, 0xf2, 0x5c, 0x19, 0xe6, 0x74, 0xbb,
  0x02, 0x9a, 0x4f, 0xd8, 0x61, 0x37, 0xce, 0x85, 0xe0, 0x2b, 0x7d, 0x46, 0xa9, 0x13, 0xf5, 0x6c
};

static int hmac_sha256(const uint8_t *key, size_t key_len,
                       const uint8_t *msg, size_t msg_len,
                       uint8_t out[SECURE_MAC_SIZE])
{
  uint8_t k0[SHA256_BLOCK_SIZE] = {0};
  uint8_t pad[SHA256_BLOCK_SIZE];
  uint8_t inner[SECURE_MAC_SIZE];
  mbedtls_sha256_context ctx;
  int ret;

  /* K0: keys longer than the block size are hashed first, shorter ones zero-padded. */
  if (key_len > SHA256_BLOCK_SIZE)
  {
    ret = mbedtls_sha256(key, key_len, k0, 0);
    if (ret != 0)
    {
      goto cleanup_keys;
    }
  }
  else
  {
    memcpy(k0, key, key_len);
  }

  mbedtls_sha256_init(&ctx);

  /* inner = H((K0 ^ ipad) || msg) */
  for (size_t i = 0U; i < SHA256_BLOCK_SIZE; i++)
  {
    pad[i] = k0[i] ^ 0x36U;
  }
  if ((ret = mbedtls_sha256_starts(&ctx, 0)) != 0 ||
      (ret = mbedtls_sha256_update(&ctx, pad, sizeof(pad))) != 0 ||
      (ret = mbedtls_sha256_update(&ctx, msg, msg_len)) != 0 ||
      (ret = mbedtls_sha256_finish(&ctx, inner)) != 0)
  {
    goto cleanup;
  }

  /* out = H((K0 ^ opad) || inner) */
  for (size_t i = 0U; i < SHA256_BLOCK_SIZE; i++)
  {
    pad[i] = k0[i] ^ 0x5cU;
  }
  if ((ret = mbedtls_sha256_starts(&ctx, 0)) != 0 ||
      (ret = mbedtls_sha256_update(&ctx, pad, sizeof(pad))) != 0 ||
      (ret = mbedtls_sha256_update(&ctx, inner, sizeof(inner))) != 0 ||
      (ret = mbedtls_sha256_finish(&ctx, out)) != 0)
  {
    goto cleanup;
  }

cleanup:
  mbedtls_sha256_free(&ctx);
  mbedtls_platform_zeroize(inner, sizeof(inner));
cleanup_keys:
  mbedtls_platform_zeroize(k0, sizeof(k0));
  mbedtls_platform_zeroize(pad, sizeof(pad));
  return ret;
}

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

/* ---------------------------- NSC entry points ---------------------------- */

CMSE_NS_ENTRY secure_status_t SECURE_CryptoSelfTest(void)
{
  /* RFC 4231 test cases 1, 2 and 6 (6 exercises the hashed long-key path). */
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
  uint8_t mac[SECURE_MAC_SIZE];
  uint32_t fail = 0U;

  memset(key, 0x0b, 20);
  fail |= (uint32_t)hmac_sha256(key, 20, tc1_data, sizeof(tc1_data) - 1U, mac);
  fail |= ct_compare(mac, tc1_mac, sizeof(mac));

  fail |= (uint32_t)hmac_sha256(tc2_key, sizeof(tc2_key) - 1U, tc2_data, sizeof(tc2_data) - 1U, mac);
  fail |= ct_compare(mac, tc2_mac, sizeof(mac));

  memset(key, 0xaa, sizeof(key));
  fail |= (uint32_t)hmac_sha256(key, sizeof(key), tc6_data, sizeof(tc6_data) - 1U, mac);
  fail |= ct_compare(mac, tc6_mac, sizeof(mac));

  mbedtls_platform_zeroize(mac, sizeof(mac));
  return (fail == 0U) ? SECURE_OK : SECURE_ERR_SELFTEST;
}

CMSE_NS_ENTRY secure_status_t SECURE_MAC_Compute(const uint8_t *msg, uint32_t len,
                                                 uint8_t mac[SECURE_MAC_SIZE])
{
  uint8_t tag[SECURE_MAC_SIZE];

  if (!ns_buffer_ok(msg, len, CMSE_MPU_READ) ||
      mac == NULL || !ns_buffer_ok(mac, SECURE_MAC_SIZE, CMSE_MPU_READWRITE))
  {
    return SECURE_ERR_PARAM;
  }

  /* Compute into Secure memory, then copy out, so a failure never leaves a partial tag. */
  if (hmac_sha256(device_key, sizeof(device_key), msg, len, tag) != 0)
  {
    mbedtls_platform_zeroize(tag, sizeof(tag));
    return SECURE_ERR_INTERNAL;
  }
  memcpy(mac, tag, sizeof(tag));
  mbedtls_platform_zeroize(tag, sizeof(tag));
  return SECURE_OK;
}

CMSE_NS_ENTRY secure_status_t SECURE_MAC_Verify(const uint8_t *msg, uint32_t len,
                                                const uint8_t mac[SECURE_MAC_SIZE])
{
  uint8_t tag[SECURE_MAC_SIZE];
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
  mbedtls_platform_zeroize(tag, sizeof(tag));
  return status;
}
