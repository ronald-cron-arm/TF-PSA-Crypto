/*
 * SM2 digital signature primitives
 */
/*
 * Copyright The Mbed TLS Contributors
 * SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "tf_psa_crypto_common.h"

#if defined(MBEDTLS_PSA_BUILTIN_ALG_SM2DSA)

#include "sm2_internal.h"
#include "bignum_internal.h"
#include "psa_crypto_core.h"
#include "psa_crypto_ecp.h"
#include "psa_crypto_random_impl.h"
#include "psa_util_internal.h"

#include "mbedtls/private/error_common.h"
#include "mbedtls/platform.h"
#include "mbedtls/platform_util.h"

#include <string.h>

#define SM2_CURVE_BYTES 32

static int sm2_read_hash(mbedtls_mpi *e,
                         const unsigned char *hash, size_t hash_length,
                         const mbedtls_mpi *n)
{
    int ret = mbedtls_mpi_read_binary(e, hash, hash_length);
    if (ret == 0) {
        ret = mbedtls_mpi_mod_mpi(e, e, n);
    }
    return ret;
}

static psa_status_t sm2_hash_mpi(psa_hash_operation_t *operation,
                                 const mbedtls_mpi *value,
                                 unsigned char buffer[SM2_CURVE_BYTES])
{
    int ret = mbedtls_mpi_write_binary(value, buffer, SM2_CURVE_BYTES);
    if (ret != 0) {
        return mbedtls_to_psa_error(ret);
    }
    return psa_hash_update(operation, buffer, SM2_CURVE_BYTES);
}

static psa_status_t tf_psa_crypto_sm2_compute_z_internal(
    psa_algorithm_t hash_alg,
    const mbedtls_ecp_group *grp,
    const mbedtls_ecp_point *public_key,
    const unsigned char *identity,
    size_t identity_length,
    unsigned char *output, size_t output_size, size_t *output_length)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    unsigned char buffer[SM2_CURVE_BYTES];
    unsigned char entl[2];
    psa_hash_operation_t operation = PSA_HASH_OPERATION_INIT;

    if (!PSA_ALG_IS_HASH(hash_alg) || grp == NULL || public_key == NULL ||
        output == NULL || output_length == NULL ||
        (identity == NULL && identity_length != 0) ||
        grp->pbits != 256 || identity_length > 8191) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    status = mbedtls_to_psa_error(mbedtls_ecp_check_pubkey(grp, public_key));
    if (status != PSA_SUCCESS) {
        return status;
    }

    entl[0] = (unsigned char) ((identity_length * 8) >> 8);
    entl[1] = (unsigned char) (identity_length * 8);

    *output_length = 0;
    status = psa_hash_setup(&operation, hash_alg);
    if (status != PSA_SUCCESS ||
        (status = psa_hash_update(&operation, entl, sizeof(entl))) != PSA_SUCCESS ||
        (status = psa_hash_update(&operation, identity,
                                  identity_length)) != PSA_SUCCESS) {
        goto cleanup;
    }

    if ((status = sm2_hash_mpi(&operation, &grp->A, buffer)) != PSA_SUCCESS ||
        (status = sm2_hash_mpi(&operation, &grp->B, buffer)) != PSA_SUCCESS ||
        (status = sm2_hash_mpi(&operation, &grp->G.X, buffer)) != PSA_SUCCESS ||
        (status = sm2_hash_mpi(&operation, &grp->G.Y, buffer)) != PSA_SUCCESS ||
        (status = sm2_hash_mpi(&operation, &public_key->X,
                               buffer)) != PSA_SUCCESS ||
        (status = sm2_hash_mpi(&operation, &public_key->Y,
                               buffer)) != PSA_SUCCESS) {
        goto cleanup;
    }

    status = psa_hash_finish(&operation, output, output_size, output_length);

cleanup:
    psa_hash_abort(&operation);
    mbedtls_platform_zeroize(buffer, sizeof(buffer));
    return status;
}

psa_status_t tf_psa_crypto_sm2_compute_z(
    psa_algorithm_t hash_alg,
    const uint8_t *public_key, size_t public_key_length,
    const uint8_t *identity, size_t identity_length,
    uint8_t *output, size_t output_size, size_t *output_length)
{
    psa_status_t status;
    mbedtls_ecp_keypair *ecp = NULL;

    if (output_length == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    *output_length = 0;
    status = mbedtls_psa_ecp_load_representation(
        PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SM2), 256,
        public_key, public_key_length, &ecp);
    if (status != PSA_SUCCESS) {
        return status;
    }

    status = tf_psa_crypto_sm2_compute_z_internal(
        hash_alg, &ecp->grp, &ecp->Q, identity, identity_length,
        output, output_size, output_length);
    mbedtls_ecp_keypair_free(ecp);
    mbedtls_free(ecp);
    if (status != PSA_SUCCESS) {
        return status;
    }
    return PSA_SUCCESS;
}

static int sm2_sign_with_k(mbedtls_ecp_group *grp,
                           mbedtls_mpi *r,
                           mbedtls_mpi *s,
                           const mbedtls_mpi *d,
                           const unsigned char *hash, size_t hash_length,
                           const mbedtls_mpi *k,
                           int (*f_rng)(void *, unsigned char *, size_t),
                           void *p_rng)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_ecp_point point;
    mbedtls_mpi e, d_plus_one_inv, tmp;

    mbedtls_ecp_point_init(&point);
    mbedtls_mpi_init(&e);
    mbedtls_mpi_init(&d_plus_one_inv);
    mbedtls_mpi_init(&tmp);

    MBEDTLS_MPI_CHK(mbedtls_ecp_check_privkey(grp, d));
    MBEDTLS_MPI_CHK(mbedtls_ecp_check_privkey(grp, k));
    MBEDTLS_MPI_CHK(sm2_read_hash(&e, hash, hash_length, &grp->N));
    MBEDTLS_MPI_CHK(mbedtls_mpi_add_int(&tmp, d, 1));
    if (mbedtls_mpi_cmp_mpi(&tmp, &grp->N) == 0) {
        ret = MBEDTLS_ERR_ECP_INVALID_KEY;
        goto cleanup;
    }
    MBEDTLS_MPI_CHK(mbedtls_mpi_gcd_modinv_odd(NULL, &d_plus_one_inv,
                                                &tmp, &grp->N));
    MBEDTLS_MPI_CHK(mbedtls_ecp_mul(grp, &point, k, &grp->G,
                                    f_rng, p_rng));

    MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(r, &e, &point.X));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(r, r, &grp->N));
    if (mbedtls_mpi_cmp_int(r, 0) == 0) {
        ret = MBEDTLS_ERR_ECP_RANDOM_FAILED;
        goto cleanup;
    }

    MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(&tmp, r, k));
    if (mbedtls_mpi_cmp_mpi(&tmp, &grp->N) == 0) {
        ret = MBEDTLS_ERR_ECP_RANDOM_FAILED;
        goto cleanup;
    }

    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&tmp, r, d));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&tmp, &tmp, &grp->N));
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&tmp, k, &tmp));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&tmp, &tmp, &grp->N));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(s, &d_plus_one_inv, &tmp));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(s, s, &grp->N));
    if (mbedtls_mpi_cmp_int(s, 0) == 0) {
        ret = MBEDTLS_ERR_ECP_RANDOM_FAILED;
    }

cleanup:
    mbedtls_ecp_point_free(&point);
    mbedtls_mpi_free(&e);
    mbedtls_mpi_free(&d_plus_one_inv);
    mbedtls_mpi_free(&tmp);
    return ret;
}

static int sm2_verify(mbedtls_ecp_group *grp,
                      const unsigned char *hash, size_t hash_length,
                      const mbedtls_ecp_point *public_key,
                      const mbedtls_mpi *r,
                      const mbedtls_mpi *s)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_ecp_point point;
    mbedtls_mpi e, t;

    if (mbedtls_mpi_cmp_int(r, 1) < 0 ||
        mbedtls_mpi_cmp_mpi(r, &grp->N) >= 0 ||
        mbedtls_mpi_cmp_int(s, 1) < 0 ||
        mbedtls_mpi_cmp_mpi(s, &grp->N) >= 0) {
        return MBEDTLS_ERR_ECP_VERIFY_FAILED;
    }
    if ((ret = mbedtls_ecp_check_pubkey(grp, public_key)) != 0) {
        return ret;
    }

    mbedtls_ecp_point_init(&point);
    mbedtls_mpi_init(&e);
    mbedtls_mpi_init(&t);

    MBEDTLS_MPI_CHK(sm2_read_hash(&e, hash, hash_length, &grp->N));
    MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(&t, r, s));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&t, &t, &grp->N));
    if (mbedtls_mpi_cmp_int(&t, 0) == 0) {
        ret = MBEDTLS_ERR_ECP_VERIFY_FAILED;
        goto cleanup;
    }

    MBEDTLS_MPI_CHK(mbedtls_ecp_muladd(grp, &point, s, &grp->G,
                                       &t, public_key));
    if (mbedtls_ecp_is_zero(&point)) {
        ret = MBEDTLS_ERR_ECP_VERIFY_FAILED;
        goto cleanup;
    }
    MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(&point.X, &e, &point.X));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&point.X, &point.X, &grp->N));
    if (mbedtls_mpi_cmp_mpi(&point.X, r) != 0) {
        ret = MBEDTLS_ERR_ECP_VERIFY_FAILED;
    }

cleanup:
    mbedtls_ecp_point_free(&point);
    mbedtls_mpi_free(&e);
    mbedtls_mpi_free(&t);
    return ret;
}

psa_status_t tf_psa_crypto_sm2_sign_hash(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg, const uint8_t *hash, size_t hash_length,
    uint8_t *signature, size_t signature_size, size_t *signature_length)
{
    psa_status_t status;
    size_t expected_hash_length = PSA_HASH_LENGTH(PSA_ALG_SIGN_GET_HASH(alg));
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned tries = 0;
    mbedtls_ecp_keypair *ecp = NULL;
    mbedtls_mpi r, s, k;

    if (!PSA_ALG_IS_SM2DSA(alg) || expected_hash_length == 0 ||
        hash_length != expected_hash_length ||
        attributes->type != PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SM2) ||
        attributes->bits != 256) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (signature_size < 2 * SM2_CURVE_BYTES) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    status = mbedtls_psa_ecp_load_representation(attributes->type,
                                                  attributes->bits,
                                                  key_buffer,
                                                  key_buffer_size,
                                                  &ecp);
    if (status != PSA_SUCCESS) {
        return status;
    }

    /* SM2 private keys are in [1, n-2], since (1 + d)^-1 is required. */
    if (mbedtls_mpi_cmp_int(&ecp->d, 1) < 0 ||
        mbedtls_mpi_cmp_mpi(&ecp->d, &ecp->grp.N) >= 0) {
        ret = MBEDTLS_ERR_ECP_INVALID_KEY;
        goto cleanup_key;
    }

    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);
    mbedtls_mpi_init(&k);

    do {
        if (tries++ >= 10) {
            ret = MBEDTLS_ERR_ECP_RANDOM_FAILED;
            goto cleanup;
        }

        MBEDTLS_MPI_CHK(mbedtls_ecp_gen_privkey(
                            &ecp->grp, &k, mbedtls_psa_get_random,
                            MBEDTLS_PSA_RANDOM_STATE));
        ret = sm2_sign_with_k(&ecp->grp, &r, &s, &ecp->d,
                              hash, hash_length, &k,
                              mbedtls_psa_get_random,
                              MBEDTLS_PSA_RANDOM_STATE);
    } while (ret == MBEDTLS_ERR_ECP_RANDOM_FAILED);
    MBEDTLS_MPI_CHK(ret);

    MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&r, signature, SM2_CURVE_BYTES));
    MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(
                        &s, signature + SM2_CURVE_BYTES, SM2_CURVE_BYTES));
    *signature_length = 2 * SM2_CURVE_BYTES;

cleanup:
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    mbedtls_mpi_free(&k);
cleanup_key:
    mbedtls_ecp_keypair_free(ecp);
    mbedtls_free(ecp);
    return mbedtls_to_psa_error(ret);
}

psa_status_t tf_psa_crypto_sm2_verify_hash(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg, const uint8_t *hash, size_t hash_length,
    const uint8_t *signature, size_t signature_length)
{
    psa_status_t status;
    size_t expected_hash_length = PSA_HASH_LENGTH(PSA_ALG_SIGN_GET_HASH(alg));
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_ecp_keypair *ecp = NULL;
    mbedtls_mpi r, s;

    if (!PSA_ALG_IS_SM2DSA(alg) || expected_hash_length == 0 ||
        hash_length != expected_hash_length ||
        PSA_KEY_TYPE_ECC_GET_FAMILY(attributes->type) != PSA_ECC_FAMILY_SM2 ||
        attributes->bits != 256) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (signature_length != 2 * SM2_CURVE_BYTES) {
        return PSA_ERROR_INVALID_SIGNATURE;
    }

    status = mbedtls_psa_ecp_load_representation(attributes->type,
                                                  attributes->bits,
                                                  key_buffer,
                                                  key_buffer_size,
                                                  &ecp);
    if (status != PSA_SUCCESS) {
        return status;
    }

    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&r, signature, SM2_CURVE_BYTES));
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(
                        &s, signature + SM2_CURVE_BYTES, SM2_CURVE_BYTES));
    status = mbedtls_psa_ecp_load_public_part(ecp);
    if (status != PSA_SUCCESS) {
        ret = MBEDTLS_ERR_ECP_INVALID_KEY;
        goto cleanup;
    }
    ret = sm2_verify(&ecp->grp, hash, hash_length, &ecp->Q, &r, &s);

cleanup:
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    mbedtls_ecp_keypair_free(ecp);
    mbedtls_free(ecp);
    return mbedtls_to_psa_error(ret);
}

#if defined(MBEDTLS_SELF_TEST)

static int sm2_self_test_rng(void *state, unsigned char *output, size_t length)
{
    (void) state;
    memset(output, 0x2a, length);
    return 0;
}

int tf_psa_crypto_sm2_self_test(int verbose)
{
    static const unsigned char identity[] = "ALICE123@YAHOO.COM";
    static const unsigned char expected_z[32] = {
        0xf4, 0xa3, 0x84, 0x89, 0xe3, 0x2b, 0x45, 0xb6,
        0xf8, 0x76, 0xe3, 0xac, 0x21, 0x68, 0xca, 0x39,
        0x23, 0x62, 0xdc, 0x8f, 0x23, 0x45, 0x9c, 0x1d,
        0x11, 0x46, 0xfc, 0x3d, 0xbf, 0xb7, 0xbc, 0x9a
    };
    static const unsigned char hash[] = {
        0xb5, 0x24, 0xf5, 0x52, 0xcd, 0x82, 0xb8, 0xb0,
        0x28, 0x47, 0x6e, 0x00, 0x5c, 0x37, 0x7f, 0xb1,
        0x9a, 0x87, 0xe6, 0xfc, 0x68, 0x2d, 0x48, 0xbb,
        0x5d, 0x42, 0xe3, 0xd9, 0xb9, 0xef, 0xfe, 0x76
    };
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char z[sizeof(expected_z)];
    size_t z_length = 0;
    mbedtls_ecp_group grp;
    mbedtls_ecp_point public_key;
    mbedtls_mpi d, k, r, s, expected_r, expected_s;

    if (verbose != 0) {
        mbedtls_printf("  SM2 test (GM/T 0003.2-2012 Annex A.2): ");
    }

    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&public_key);
    mbedtls_mpi_init(&d);
    mbedtls_mpi_init(&k);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);
    mbedtls_mpi_init(&expected_r);
    mbedtls_mpi_init(&expected_s);

    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(
                        &grp.P, 16,
                        "8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3"));
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(
                        &grp.A, 16,
                        "787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498"));
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(
                        &grp.B, 16,
                        "63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A"));
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(
                        &grp.G.X, 16,
                        "421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D"));
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(
                        &grp.G.Y, 16,
                        "0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2"));
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&grp.G.Z, 1));
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(
                        &grp.N, 16,
                        "8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7"));
    grp.pbits = mbedtls_mpi_bitlen(&grp.P);
    grp.nbits = mbedtls_mpi_bitlen(&grp.N);

    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(
                        &d, 16,
                        "128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263"));
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(
                        &public_key.X, 16,
                        "0AE4C7798AA0F119471BEE11825BE46202BB79E2A5844495E97C04FF4DF2548A"));
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(
                        &public_key.Y, 16,
                        "7C0240F88F1CD4E16352A73C17B7F16F07353E53A176D684A9FE0C6BB798E857"));
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&public_key.Z, 1));
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(
                        &k, 16,
                        "6CB28D99385C175C94F94E934817663FC176D925DD72B727260DBAAE1FB2F96F"));
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(
                        &expected_r, 16,
                        "40F1EC59F793D9F49E09DCEF49130D4194F79FB1EED2CAA55BACDB49C4E755D1"));
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(
                        &expected_s, 16,
                        "6FC6DAC32C5D5CF10C77DFB20F7C2EB667A457872FB09EC56327A67EC7DEEBE7"));

    MBEDTLS_MPI_CHK(tf_psa_crypto_sm2_compute_z_internal(
                        PSA_ALG_SM3, &grp, &public_key,
                        identity, sizeof(identity) - 1,
                        z, sizeof(z), &z_length));
    if (z_length != sizeof(expected_z) ||
        memcmp(z, expected_z, sizeof(z)) != 0) {
        ret = 1;
        goto cleanup;
    }

    MBEDTLS_MPI_CHK(sm2_sign_with_k(&grp, &r, &s, &d,
                                     hash, sizeof(hash), &k,
                                     sm2_self_test_rng, NULL));
    if (mbedtls_mpi_cmp_mpi(&r, &expected_r) != 0 ||
        mbedtls_mpi_cmp_mpi(&s, &expected_s) != 0) {
        ret = 1;
        goto cleanup;
    }
    MBEDTLS_MPI_CHK(sm2_verify(&grp, hash, sizeof(hash),
                               &public_key, &r, &s));

cleanup:
    if (verbose != 0) {
        mbedtls_printf(ret == 0 ? "passed\n\n" : "failed\n\n");
    }
    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&public_key);
    mbedtls_mpi_free(&d);
    mbedtls_mpi_free(&k);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    mbedtls_mpi_free(&expected_r);
    mbedtls_mpi_free(&expected_s);
    mbedtls_platform_zeroize(z, sizeof(z));
    return ret;
}

#endif /* MBEDTLS_SELF_TEST */

#endif /* MBEDTLS_PSA_BUILTIN_ALG_SM2DSA */
