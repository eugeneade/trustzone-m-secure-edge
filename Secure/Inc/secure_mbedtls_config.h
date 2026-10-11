/*
 * Minimal mbedTLS configuration for the Secure world.
 *
 * Only SHA-256 is built; HMAC is layered on top in crypto_service.c so the
 * Secure image needs no heap (mbedtls_md_hmac_* allocates its context).
 */
#ifndef SECURE_MBEDTLS_CONFIG_H
#define SECURE_MBEDTLS_CONFIG_H

#define MBEDTLS_SHA256_C

#endif /* SECURE_MBEDTLS_CONFIG_H */
