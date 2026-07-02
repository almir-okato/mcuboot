/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * ESP32-H4 ROM linker scripts omit RSA-PSS helpers (IDF-12262). Provide weak
 * stubs so CI secure-boot image builds link until ROM exports are available.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "rsa_pss.h"

bool __attribute__((weak)) ets_rsa_pss_verify(const ets_rsa_pubkey_t *key,
                                              const uint8_t *sig,
                                              const uint8_t *digest,
                                              uint8_t *verified_digest)
{
    (void)key;
    (void)sig;
    (void)digest;
    (void)verified_digest;
    return false;
}

void __attribute__((weak)) ets_mgf1_sha256(const uint8_t *mgf_seed,
                                             size_t seed_len,
                                             size_t mask_len,
                                             uint8_t *mask)
{
    (void)mgf_seed;
    (void)seed_len;
    (void)mask_len;
    (void)mask;
}

bool __attribute__((weak)) ets_emsa_pss_verify(const uint8_t *encoded_message,
                                               const uint8_t *mhash)
{
    (void)encoded_message;
    (void)mhash;
    return false;
}
