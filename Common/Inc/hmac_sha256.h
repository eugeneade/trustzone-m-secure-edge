/*
 * HMAC-SHA256 (RFC 2104) on top of mbedTLS SHA-256, no heap.
 *
 * Built into both images: the Secure world uses it for the crypto service,
 * the Non-Secure world uses the identical code as the M3 baseline.
 */
#ifndef HMAC_SHA256_H
#define HMAC_SHA256_H

#include <stddef.h>
#include <stdint.h>

#define HMAC_SHA256_SIZE  32U

/* out = HMAC-SHA256(key, msg). Returns 0 on success, an mbedTLS error otherwise. */
int hmac_sha256(const uint8_t *key, size_t key_len,
                const uint8_t *msg, size_t msg_len,
                uint8_t out[HMAC_SHA256_SIZE]);

#endif /* HMAC_SHA256_H */
