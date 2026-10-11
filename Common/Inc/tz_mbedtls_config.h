/*
 * Minimal mbedTLS configuration, shared by both images.
 *
 * Only SHA-256 is built; HMAC is layered on top in hmac_sha256.c so the
 * firmware needs no heap (mbedtls_md_hmac_* allocates its context).
 */
#ifndef TZ_MBEDTLS_CONFIG_H
#define TZ_MBEDTLS_CONFIG_H

#define MBEDTLS_SHA256_C

#endif /* TZ_MBEDTLS_CONFIG_H */
