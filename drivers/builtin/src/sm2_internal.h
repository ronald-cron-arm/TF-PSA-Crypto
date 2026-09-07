/**
 * \file sm2_internal.h
 *
 * \brief Internal SM2 helpers.
 */
/*
 * Copyright The Mbed TLS Contributors
 * SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef TF_PSA_CRYPTO_SM2_INTERNAL_H
#define TF_PSA_CRYPTO_SM2_INTERNAL_H

#include "psa/crypto.h"
#include "mbedtls/private/ecp.h"

psa_status_t tf_psa_crypto_sm2_sign_hash(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg, const uint8_t *hash, size_t hash_length,
    uint8_t *signature, size_t signature_size, size_t *signature_length);

psa_status_t tf_psa_crypto_sm2_verify_hash(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg, const uint8_t *hash, size_t hash_length,
    const uint8_t *signature, size_t signature_length);

#if defined(MBEDTLS_SELF_TEST)
/** Run the GM/T 0003.2-2012 Annex A.2 SM2 known-answer test. */
int tf_psa_crypto_sm2_self_test(int verbose);
#endif /* MBEDTLS_SELF_TEST */

#endif /* TF_PSA_CRYPTO_SM2_INTERNAL_H */
