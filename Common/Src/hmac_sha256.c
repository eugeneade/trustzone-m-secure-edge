/*
 * HMAC-SHA256 (RFC 2104) on top of mbedTLS SHA-256.
 *
 * Used instead of mbedtls_md_hmac_*, which allocates its context on the
 * heap. Correctness is checked against the RFC 4231 test vectors by
 * SECURE_CryptoSelfTest().
 */
#include <string.h>
#include "mbedtls/sha256.h"
#include "mbedtls/platform_util.h"
#include "hmac_sha256.h"

#define SHA256_BLOCK_SIZE  64U

int hmac_sha256(const uint8_t *key, size_t key_len,
                const uint8_t *msg, size_t msg_len,
                uint8_t out[HMAC_SHA256_SIZE])
{
  uint8_t k0[SHA256_BLOCK_SIZE] = {0};
  uint8_t pad[SHA256_BLOCK_SIZE];
  uint8_t inner[HMAC_SHA256_SIZE];
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
