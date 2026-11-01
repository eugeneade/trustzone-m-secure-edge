/*
 * HMAC-SHA256 on the STM32L5 HASH peripheral (Secure world only).
 */
#ifndef HASH_HW_H
#define HASH_HW_H

#include <stddef.h>
#include <stdint.h>

#define HASH_HW_MAC_SIZE  32U

/* Enables the HASH clock. The peripheral is made Secure by gtzc setup in main.c. */
void hash_hw_init(void);

/* M6 latency diagnosis: phase marker (see hash_phase_t in secure_nsc.h). */
void hash_hw_set_phase_marker(volatile uint32_t *marker);

/* out = HMAC-SHA256(key, msg) computed by the HASH peripheral.
 * Returns 0 on success, -1 if the peripheral timed out. Not reentrant: callers
 * must serialise (see SECURE_MAC_ComputeHw). */
int hash_hw_hmac_sha256(const uint8_t *key, size_t key_len,
                        const uint8_t *msg, size_t msg_len,
                        uint8_t out[HASH_HW_MAC_SIZE]);

#endif /* HASH_HW_H */
