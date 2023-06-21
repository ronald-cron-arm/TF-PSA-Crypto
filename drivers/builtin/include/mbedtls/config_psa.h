/**
 * \file mbedtls/config_psa.h
 * \brief PSA crypto configuration options (set of defines)
 *
 *  This set of compile-time options takes settings defined in
 *  include/mbedtls/mbedtls_config.h and include/psa/crypto_config.h and uses
 *  those definitions to define symbols used in the library code.
 *
 *  Users and integrators should not edit this file, please edit
 *  include/mbedtls/mbedtls_config.h for MBEDTLS_XXX settings or
 *  include/psa/crypto_config.h for PSA_WANT_XXX settings.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#ifndef MBEDTLS_CONFIG_PSA_H
#define MBEDTLS_CONFIG_PSA_H

#if defined(MBEDTLS_PSA_CRYPTO_CONFIG)
#if defined(PSA_CRYPTO_CONFIG_FILE)
#include PSA_CRYPTO_CONFIG_FILE
#else
#include "psa/crypto_config.h"
#endif
#endif /* defined(MBEDTLS_PSA_CRYPTO_CONFIG) */

#if defined(MBEDTLS_PSA_CRYPTO_USER_CONFIG_FILE)
#include MBEDTLS_PSA_CRYPTO_USER_CONFIG_FILE
#endif

#ifdef __cplusplus
extern "C" {
#endif



/****************************************************************/
/* De facto synonyms */
/****************************************************************/

#if defined(PSA_WANT_ALG_ECDSA_ANY) && !defined(PSA_WANT_ALG_ECDSA)
#define PSA_WANT_ALG_ECDSA PSA_WANT_ALG_ECDSA_ANY
#elif !defined(PSA_WANT_ALG_ECDSA_ANY) && defined(PSA_WANT_ALG_ECDSA)
#define PSA_WANT_ALG_ECDSA_ANY PSA_WANT_ALG_ECDSA
#endif

#if defined(PSA_WANT_ALG_CCM_STAR_NO_TAG) && !defined(PSA_WANT_ALG_CCM)
#define PSA_WANT_ALG_CCM PSA_WANT_ALG_CCM_STAR_NO_TAG
#elif !defined(PSA_WANT_ALG_CCM_STAR_NO_TAG) && defined(PSA_WANT_ALG_CCM)
#define PSA_WANT_ALG_CCM_STAR_NO_TAG PSA_WANT_ALG_CCM
#endif

#if defined(PSA_WANT_ALG_RSA_PKCS1V15_SIGN_RAW) && !defined(PSA_WANT_ALG_RSA_PKCS1V15_SIGN)
#define PSA_WANT_ALG_RSA_PKCS1V15_SIGN PSA_WANT_ALG_RSA_PKCS1V15_SIGN_RAW
#elif !defined(PSA_WANT_ALG_RSA_PKCS1V15_SIGN_RAW) && defined(PSA_WANT_ALG_RSA_PKCS1V15_SIGN)
#define PSA_WANT_ALG_RSA_PKCS1V15_SIGN_RAW PSA_WANT_ALG_RSA_PKCS1V15_SIGN
#endif

#if defined(PSA_WANT_ALG_RSA_PSS_ANY_SALT) && !defined(PSA_WANT_ALG_RSA_PSS)
#define PSA_WANT_ALG_RSA_PSS PSA_WANT_ALG_RSA_PSS_ANY_SALT
#elif !defined(PSA_WANT_ALG_RSA_PSS_ANY_SALT) && defined(PSA_WANT_ALG_RSA_PSS)
#define PSA_WANT_ALG_RSA_PSS_ANY_SALT PSA_WANT_ALG_RSA_PSS
#endif


/****************************************************************/
/* Hashes that are built in are also enabled in PSA.
 * This simplifies dependency declarations especially
 * for modules that obey MBEDTLS_USE_PSA_CRYPTO. */
/****************************************************************/

#if defined(MBEDTLS_MD5_C)
#define PSA_WANT_ALG_MD5 1
#endif

#if defined(MBEDTLS_RIPEMD160_C)
#define PSA_WANT_ALG_RIPEMD160 1
#endif

#if defined(MBEDTLS_SHA1_C)
#define PSA_WANT_ALG_SHA_1 1
#endif

#if defined(MBEDTLS_SHA224_C)
#define PSA_WANT_ALG_SHA_224 1
#endif

#if defined(MBEDTLS_SHA256_C)
#define PSA_WANT_ALG_SHA_256 1
#endif

#if defined(MBEDTLS_SHA384_C)
#define PSA_WANT_ALG_SHA_384 1
#endif

#if defined(MBEDTLS_SHA512_C)
#define PSA_WANT_ALG_SHA_512 1
#endif


/****************************************************************/
/* Require built-in implementations based on PSA requirements */
/****************************************************************/

#if defined(MBEDTLS_PSA_CRYPTO_CONFIG)

#if defined(PSA_WANT_ALG_DETERMINISTIC_ECDSA)
#if !defined(MBEDTLS_PSA_ACCEL_ALG_DETERMINISTIC_ECDSA)
#define MBEDTLS_PSA_BUILTIN_ALG_DETERMINISTIC_ECDSA 1
#define MBEDTLS_ECDSA_DETERMINISTIC
#define MBEDTLS_ECDSA_C
#define MBEDTLS_HMAC_DRBG_C
#define MBEDTLS_MD_C
#endif /* !MBEDTLS_PSA_ACCEL_ALG_DETERMINISTIC_ECDSA */
#endif /* PSA_WANT_ALG_DETERMINISTIC_ECDSA */

#if defined(PSA_WANT_ALG_ECDH)
#if !defined(MBEDTLS_PSA_ACCEL_ALG_ECDH)
#define MBEDTLS_PSA_BUILTIN_ALG_ECDH 1
#define MBEDTLS_ECDH_C
#define MBEDTLS_ECP_C
#define MBEDTLS_BIGNUM_C
#endif /* !MBEDTLS_PSA_ACCEL_ALG_ECDH */
#endif /* PSA_WANT_ALG_ECDH */

#if defined(PSA_WANT_ALG_ECDSA)
#if !defined(MBEDTLS_PSA_ACCEL_ALG_ECDSA)
#define MBEDTLS_PSA_BUILTIN_ALG_ECDSA 1
#define MBEDTLS_ECDSA_C
#define MBEDTLS_ECP_C
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C
#endif /* !MBEDTLS_PSA_ACCEL_ALG_ECDSA */
#endif /* PSA_WANT_ALG_ECDSA */

#if defined(PSA_WANT_ALG_FFDH)
#if !defined(MBEDTLS_PSA_ACCEL_ALG_FFDH)
#define MBEDTLS_PSA_BUILTIN_ALG_FFDH 1
#define MBEDTLS_BIGNUM_C
#endif /* !MBEDTLS_PSA_ACCEL_ALG_FFDH */
#endif /* PSA_WANT_ALG_FFDH */

#if defined(PSA_WANT_ALG_HKDF)
#if !defined(MBEDTLS_PSA_ACCEL_ALG_HKDF)
#define MBEDTLS_PSA_BUILTIN_ALG_HMAC 1
#define MBEDTLS_PSA_BUILTIN_ALG_HKDF 1
#endif /* !MBEDTLS_PSA_ACCEL_ALG_HKDF */
#endif /* PSA_WANT_ALG_HKDF */

#if defined(PSA_WANT_ALG_HKDF_EXTRACT)
#if !defined(MBEDTLS_PSA_ACCEL_ALG_HKDF_EXTRACT)
#define MBEDTLS_PSA_BUILTIN_ALG_HMAC 1
#define MBEDTLS_PSA_BUILTIN_ALG_HKDF_EXTRACT 1
#endif /* !MBEDTLS_PSA_ACCEL_ALG_HKDF_EXTRACT */
#endif /* PSA_WANT_ALG_HKDF_EXTRACT */

#if defined(PSA_WANT_ALG_HKDF_EXPAND)
#if !defined(MBEDTLS_PSA_ACCEL_ALG_HKDF_EXPAND)
#define MBEDTLS_PSA_BUILTIN_ALG_HMAC 1
#define MBEDTLS_PSA_BUILTIN_ALG_HKDF_EXPAND 1
#endif /* !MBEDTLS_PSA_ACCEL_ALG_HKDF_EXPAND */
#endif /* PSA_WANT_ALG_HKDF_EXPAND */

#if defined(PSA_WANT_ALG_HMAC)
#if !defined(MBEDTLS_PSA_ACCEL_ALG_HMAC)
#define MBEDTLS_PSA_BUILTIN_ALG_HMAC 1
#endif /* !MBEDTLS_PSA_ACCEL_ALG_HMAC */
#endif /* PSA_WANT_ALG_HMAC */

#if defined(PSA_WANT_ALG_MD5) && !defined(MBEDTLS_PSA_ACCEL_ALG_MD5)
#define MBEDTLS_PSA_BUILTIN_ALG_MD5 1
#define MBEDTLS_MD5_C
#endif

#if defined(PSA_WANT_ALG_JPAKE)
#if !defined(MBEDTLS_PSA_ACCEL_ALG_JPAKE)
#define MBEDTLS_PSA_BUILTIN_PAKE 1
#define MBEDTLS_PSA_BUILTIN_ALG_JPAKE 1
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_ECP_C
#define MBEDTLS_ECJPAKE_C
#endif /* MBEDTLS_PSA_ACCEL_ALG_JPAKE */
#endif /* PSA_WANT_ALG_JPAKE */

#if defined(PSA_WANT_ALG_RIPEMD160) && !defined(MBEDTLS_PSA_ACCEL_ALG_RIPEMD160)
#define MBEDTLS_PSA_BUILTIN_ALG_RIPEMD160 1
#define MBEDTLS_RIPEMD160_C
#endif

#if defined(PSA_WANT_ALG_RSA_OAEP)
#if !defined(MBEDTLS_PSA_ACCEL_ALG_RSA_OAEP)
#define MBEDTLS_PSA_BUILTIN_ALG_RSA_OAEP 1
#define MBEDTLS_RSA_C
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_OID_C
#define MBEDTLS_PKCS1_V21
#endif /* !MBEDTLS_PSA_ACCEL_ALG_RSA_OAEP */
#endif /* PSA_WANT_ALG_RSA_OAEP */

#if defined(PSA_WANT_ALG_RSA_PKCS1V15_CRYPT)
#if !defined(MBEDTLS_PSA_ACCEL_ALG_RSA_PKCS1V15_CRYPT)
#define MBEDTLS_PSA_BUILTIN_ALG_RSA_PKCS1V15_CRYPT 1
#define MBEDTLS_RSA_C
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_OID_C
#define MBEDTLS_PKCS1_V15
#endif /* !MBEDTLS_PSA_ACCEL_ALG_RSA_PKCS1V15_CRYPT */
#endif /* PSA_WANT_ALG_RSA_PKCS1V15_CRYPT */

#if defined(PSA_WANT_ALG_RSA_PKCS1V15_SIGN)
#if !defined(MBEDTLS_PSA_ACCEL_ALG_RSA_PKCS1V15_SIGN)
#define MBEDTLS_PSA_BUILTIN_ALG_RSA_PKCS1V15_SIGN 1
#define MBEDTLS_RSA_C
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_OID_C
#define MBEDTLS_PKCS1_V15
#endif /* !MBEDTLS_PSA_ACCEL_ALG_RSA_PKCS1V15_SIGN */
#endif /* PSA_WANT_ALG_RSA_PKCS1V15_SIGN */

#if defined(PSA_WANT_ALG_RSA_PSS)
#if !defined(MBEDTLS_PSA_ACCEL_ALG_RSA_PSS)
#define MBEDTLS_PSA_BUILTIN_ALG_RSA_PSS 1
#define MBEDTLS_RSA_C
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_OID_C
#define MBEDTLS_PKCS1_V21
#endif /* !MBEDTLS_PSA_ACCEL_ALG_RSA_PSS */
#endif /* PSA_WANT_ALG_RSA_PSS */

#if defined(PSA_WANT_ALG_SHA_1) && !defined(MBEDTLS_PSA_ACCEL_ALG_SHA_1)
#define MBEDTLS_PSA_BUILTIN_ALG_SHA_1 1
#define MBEDTLS_SHA1_C
#endif

#if defined(PSA_WANT_ALG_SHA_224) && !defined(MBEDTLS_PSA_ACCEL_ALG_SHA_224)
#define MBEDTLS_PSA_BUILTIN_ALG_SHA_224 1
#define MBEDTLS_SHA224_C
#endif

#if defined(PSA_WANT_ALG_SHA_256) && !defined(MBEDTLS_PSA_ACCEL_ALG_SHA_256)
#define MBEDTLS_PSA_BUILTIN_ALG_SHA_256 1
#define MBEDTLS_SHA256_C
#endif

#if defined(PSA_WANT_ALG_SHA_384) && !defined(MBEDTLS_PSA_ACCEL_ALG_SHA_384)
#define MBEDTLS_PSA_BUILTIN_ALG_SHA_384 1
#define MBEDTLS_SHA384_C
#endif

#if defined(PSA_WANT_ALG_SHA_512) && !defined(MBEDTLS_PSA_ACCEL_ALG_SHA_512)
#define MBEDTLS_PSA_BUILTIN_ALG_SHA_512 1
#define MBEDTLS_SHA512_C
#endif

#if defined(PSA_WANT_ALG_TLS12_PRF)
#if !defined(MBEDTLS_PSA_ACCEL_ALG_TLS12_PRF)
#define MBEDTLS_PSA_BUILTIN_ALG_TLS12_PRF 1
#endif /* !MBEDTLS_PSA_ACCEL_ALG_TLS12_PRF */
#endif /* PSA_WANT_ALG_TLS12_PRF */

#if defined(PSA_WANT_ALG_TLS12_PSK_TO_MS)
#if !defined(MBEDTLS_PSA_ACCEL_ALG_TLS12_PSK_TO_MS)
#define MBEDTLS_PSA_BUILTIN_ALG_TLS12_PSK_TO_MS 1
#endif /* !MBEDTLS_PSA_ACCEL_ALG_TLS12_PSK_TO_MS */
#endif /* PSA_WANT_ALG_TLS12_PSK_TO_MS */

#if defined(PSA_WANT_ALG_TLS12_ECJPAKE_TO_PMS)
#if !defined(MBEDTLS_PSA_ACCEL_ALG_TLS12_ECJPAKE_TO_PMS)
#define MBEDTLS_PSA_BUILTIN_ALG_TLS12_ECJPAKE_TO_PMS 1
#endif /* !MBEDTLS_PSA_ACCEL_ALG_TLS12_ECJPAKE_TO_PMS */
#endif /* PSA_WANT_ALG_TLS12_ECJPAKE_TO_PMS */

#if defined(PSA_WANT_KEY_TYPE_ECC_KEY_PAIR)
#if !defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR)
#define MBEDTLS_PSA_BUILTIN_KEY_TYPE_ECC_KEY_PAIR 1
#define MBEDTLS_ECP_C
#define MBEDTLS_BIGNUM_C
#endif /* !MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR */
#endif /* PSA_WANT_KEY_TYPE_ECC_KEY_PAIR */

#if defined(PSA_WANT_KEY_TYPE_DH_KEY_PAIR)
#if !defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_DH_KEY_PAIR)
#define MBEDTLS_PSA_BUILTIN_KEY_TYPE_DH_KEY_PAIR 1
#define MBEDTLS_BIGNUM_C
#endif /* !MBEDTLS_PSA_ACCEL_KEY_TYPE_DH_KEY_PAIR */
#endif /* PSA_WANT_KEY_TYPE_DH_KEY_PAIR */

#if defined(PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY)
#if !defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_PUBLIC_KEY)
#define MBEDTLS_PSA_BUILTIN_KEY_TYPE_ECC_PUBLIC_KEY 1
#define MBEDTLS_ECP_C
#define MBEDTLS_BIGNUM_C
#endif /* !MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_PUBLIC_KEY */
#endif /* PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY */

#if defined(PSA_WANT_KEY_TYPE_DH_PUBLIC_KEY)
#if !defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_DH_PUBLIC_KEY)
#define MBEDTLS_PSA_BUILTIN_KEY_TYPE_DH_PUBLIC_KEY 1
#define MBEDTLS_BIGNUM_C
#endif /* !MBEDTLS_PSA_ACCEL_KEY_TYPE_DH_PUBLIC_KEY */
#endif /* PSA_WANT_KEY_TYPE_DH_PUBLIC_KEY */

#if defined(PSA_WANT_KEY_TYPE_RSA_KEY_PAIR)
#if !defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_RSA_KEY_PAIR)
#define MBEDTLS_PSA_BUILTIN_KEY_TYPE_RSA_KEY_PAIR 1
#define MBEDTLS_RSA_C
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_OID_C
#define MBEDTLS_GENPRIME
#define MBEDTLS_PK_PARSE_C
#define MBEDTLS_PK_WRITE_C
#define MBEDTLS_PK_C
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C
#endif /* !MBEDTLS_PSA_ACCEL_KEY_TYPE_RSA_KEY_PAIR */
#endif /* PSA_WANT_KEY_TYPE_RSA_KEY_PAIR */

#if defined(PSA_WANT_KEY_TYPE_RSA_PUBLIC_KEY)
#if !defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_RSA_PUBLIC_KEY)
#define MBEDTLS_PSA_BUILTIN_KEY_TYPE_RSA_PUBLIC_KEY 1
#define MBEDTLS_RSA_C
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_OID_C
#define MBEDTLS_PK_PARSE_C
#define MBEDTLS_PK_WRITE_C
#define MBEDTLS_PK_C
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C
#endif /* !MBEDTLS_PSA_ACCEL_KEY_TYPE_RSA_PUBLIC_KEY */
#endif /* PSA_WANT_KEY_TYPE_RSA_PUBLIC_KEY */

/* If any of the block modes are requested that don't have an
 * associated HW assist, define PSA_HAVE_SOFT_BLOCK_MODE for checking
 * in the block cipher key types. */
#if (defined(PSA_WANT_ALG_CTR) && !defined(MBEDTLS_PSA_ACCEL_ALG_CTR)) || \
    (defined(PSA_WANT_ALG_CFB) && !defined(MBEDTLS_PSA_ACCEL_ALG_CFB)) || \
    (defined(PSA_WANT_ALG_OFB) && !defined(MBEDTLS_PSA_ACCEL_ALG_OFB)) || \
    defined(PSA_WANT_ALG_ECB_NO_PADDING) || \
    (defined(PSA_WANT_ALG_CBC_NO_PADDING) && \
    !defined(MBEDTLS_PSA_ACCEL_ALG_CBC_NO_PADDING)) || \
    (defined(PSA_WANT_ALG_CBC_PKCS7) && \
    !defined(MBEDTLS_PSA_ACCEL_ALG_CBC_PKCS7)) || \
    (defined(PSA_WANT_ALG_CMAC) && !defined(MBEDTLS_PSA_ACCEL_ALG_CMAC))
#define PSA_HAVE_SOFT_BLOCK_MODE 1
#endif

#if (defined(PSA_WANT_ALG_GCM) && !defined(MBEDTLS_PSA_ACCEL_ALG_GCM)) || \
    (defined(PSA_WANT_ALG_CCM) && !defined(MBEDTLS_PSA_ACCEL_ALG_CCM))
#define PSA_HAVE_SOFT_BLOCK_AEAD 1
#endif

#if defined(PSA_WANT_KEY_TYPE_AES)
#if !defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_AES)
#define PSA_HAVE_SOFT_KEY_TYPE_AES 1
#endif /* !MBEDTLS_PSA_ACCEL_KEY_TYPE_AES */
#if defined(PSA_HAVE_SOFT_KEY_TYPE_AES) || \
    defined(PSA_HAVE_SOFT_BLOCK_MODE) || \
    defined(PSA_HAVE_SOFT_BLOCK_AEAD)
#define MBEDTLS_PSA_BUILTIN_KEY_TYPE_AES 1
#define MBEDTLS_AES_C
#endif /* PSA_HAVE_SOFT_KEY_TYPE_AES || PSA_HAVE_SOFT_BLOCK_MODE */
#endif /* PSA_WANT_KEY_TYPE_AES */

#if defined(PSA_WANT_KEY_TYPE_ARIA)
#if !defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_ARIA)
#define PSA_HAVE_SOFT_KEY_TYPE_ARIA 1
#endif /* !MBEDTLS_PSA_ACCEL_KEY_TYPE_ARIA */
#if defined(PSA_HAVE_SOFT_KEY_TYPE_ARIA) || \
    defined(PSA_HAVE_SOFT_BLOCK_MODE) || \
    defined(PSA_HAVE_SOFT_BLOCK_AEAD)
#define MBEDTLS_PSA_BUILTIN_KEY_TYPE_ARIA 1
#define MBEDTLS_ARIA_C
#endif /* PSA_HAVE_SOFT_KEY_TYPE_ARIA || PSA_HAVE_SOFT_BLOCK_MODE */
#endif /* PSA_WANT_KEY_TYPE_ARIA */

#if defined(PSA_WANT_KEY_TYPE_CAMELLIA)
#if !defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_CAMELLIA)
#define PSA_HAVE_SOFT_KEY_TYPE_CAMELLIA 1
#endif /* !MBEDTLS_PSA_ACCEL_KEY_TYPE_CAMELLIA */
#if defined(PSA_HAVE_SOFT_KEY_TYPE_CAMELLIA) || \
    defined(PSA_HAVE_SOFT_BLOCK_MODE) || \
    defined(PSA_HAVE_SOFT_BLOCK_AEAD)
#define MBEDTLS_PSA_BUILTIN_KEY_TYPE_CAMELLIA 1
#define MBEDTLS_CAMELLIA_C
#endif /* PSA_HAVE_SOFT_KEY_TYPE_CAMELLIA || PSA_HAVE_SOFT_BLOCK_MODE */
#endif /* PSA_WANT_KEY_TYPE_CAMELLIA */

#if defined(PSA_WANT_KEY_TYPE_DES)
#if !defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_DES)
#define PSA_HAVE_SOFT_KEY_TYPE_DES 1
#endif /* !MBEDTLS_PSA_ACCEL_KEY_TYPE_DES */
#if defined(PSA_HAVE_SOFT_KEY_TYPE_DES) || \
    defined(PSA_HAVE_SOFT_BLOCK_MODE)
#define MBEDTLS_PSA_BUILTIN_KEY_TYPE_DES 1
#define MBEDTLS_DES_C
#endif /*PSA_HAVE_SOFT_KEY_TYPE_DES || PSA_HAVE_SOFT_BLOCK_MODE */
#endif /* PSA_WANT_KEY_TYPE_DES */

#if defined(PSA_WANT_KEY_TYPE_CHACHA20)
#if !defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_CHACHA20)
#define MBEDTLS_PSA_BUILTIN_KEY_TYPE_CHACHA20 1
#define MBEDTLS_CHACHA20_C
#endif /*!MBEDTLS_PSA_ACCEL_KEY_TYPE_CHACHA20 */
#endif /* PSA_WANT_KEY_TYPE_CHACHA20 */

/* If any of the software block ciphers are selected, define
 * PSA_HAVE_SOFT_BLOCK_CIPHER, which can be used in any of these
 * situations. */
#if defined(PSA_HAVE_SOFT_KEY_TYPE_AES) || \
    defined(PSA_HAVE_SOFT_KEY_TYPE_ARIA) || \
    defined(PSA_HAVE_SOFT_KEY_TYPE_DES) || \
    defined(PSA_HAVE_SOFT_KEY_TYPE_CAMELLIA)
#define PSA_HAVE_SOFT_BLOCK_CIPHER 1
#endif

#if defined(PSA_WANT_ALG_STREAM_CIPHER)
#define MBEDTLS_PSA_BUILTIN_ALG_STREAM_CIPHER 1
#endif /* PSA_WANT_ALG_STREAM_CIPHER */

#if defined(PSA_WANT_ALG_CBC_MAC)
#if !defined(MBEDTLS_PSA_ACCEL_ALG_CBC_MAC)
#error "CBC-MAC is not yet supported via the PSA API in Mbed TLS."
#define MBEDTLS_PSA_BUILTIN_ALG_CBC_MAC 1
#endif /* !MBEDTLS_PSA_ACCEL_ALG_CBC_MAC */
#endif /* PSA_WANT_ALG_CBC_MAC */

#if defined(PSA_WANT_ALG_CMAC)
#if !defined(MBEDTLS_PSA_ACCEL_ALG_CMAC) || \
    defined(PSA_HAVE_SOFT_BLOCK_CIPHER)
#define MBEDTLS_PSA_BUILTIN_ALG_CMAC 1
#define MBEDTLS_CMAC_C
#endif /* !MBEDTLS_PSA_ACCEL_ALG_CMAC */
#endif /* PSA_WANT_ALG_CMAC */

#if defined(PSA_WANT_ALG_CTR)
#if !defined(MBEDTLS_PSA_ACCEL_ALG_CTR) || \
    defined(PSA_HAVE_SOFT_BLOCK_CIPHER)
#define MBEDTLS_PSA_BUILTIN_ALG_CTR 1
#define MBEDTLS_CIPHER_MODE_CTR
#endif
#endif /* PSA_WANT_ALG_CTR */

#if defined(PSA_WANT_ALG_CFB)
#if !defined(MBEDTLS_PSA_ACCEL_ALG_CFB) || \
    defined(PSA_HAVE_SOFT_BLOCK_CIPHER)
#define MBEDTLS_PSA_BUILTIN_ALG_CFB 1
#define MBEDTLS_CIPHER_MODE_CFB
#endif
#endif /* PSA_WANT_ALG_CFB */

#if defined(PSA_WANT_ALG_OFB)
#if !defined(MBEDTLS_PSA_ACCEL_ALG_OFB) || \
    defined(PSA_HAVE_SOFT_BLOCK_CIPHER)
#define MBEDTLS_PSA_BUILTIN_ALG_OFB 1
#define MBEDTLS_CIPHER_MODE_OFB
#endif
#endif /* PSA_WANT_ALG_OFB */

#if defined(PSA_WANT_ALG_ECB_NO_PADDING) &&     \
    !defined(MBEDTLS_PSA_ACCEL_ALG_ECB_NO_PADDING)
#define MBEDTLS_PSA_BUILTIN_ALG_ECB_NO_PADDING 1
#endif

#if defined(PSA_WANT_ALG_CBC_NO_PADDING)
#if !defined(MBEDTLS_PSA_ACCEL_ALG_CBC_NO_PADDING) || \
    defined(PSA_HAVE_SOFT_BLOCK_CIPHER)
#define MBEDTLS_CIPHER_MODE_CBC
#define MBEDTLS_PSA_BUILTIN_ALG_CBC_NO_PADDING 1
#endif
#endif /* PSA_WANT_ALG_CBC_NO_PADDING */

#if defined(PSA_WANT_ALG_CBC_PKCS7)
#if !defined(MBEDTLS_PSA_ACCEL_ALG_CBC_PKCS7) || \
    defined(PSA_HAVE_SOFT_BLOCK_CIPHER)
#define MBEDTLS_CIPHER_MODE_CBC
#define MBEDTLS_PSA_BUILTIN_ALG_CBC_PKCS7 1
#define MBEDTLS_CIPHER_PADDING_PKCS7
#endif
#endif /* PSA_WANT_ALG_CBC_PKCS7 */

#if defined(PSA_WANT_ALG_CCM)
#if !defined(MBEDTLS_PSA_ACCEL_ALG_CCM) || \
    defined(PSA_HAVE_SOFT_KEY_TYPE_AES) || \
    defined(PSA_HAVE_SOFT_KEY_TYPE_ARIA) || \
    defined(PSA_HAVE_SOFT_KEY_TYPE_CAMELLIA)
#define MBEDTLS_PSA_BUILTIN_ALG_CCM 1
#define MBEDTLS_PSA_BUILTIN_ALG_CCM_STAR_NO_TAG 1
#define MBEDTLS_CCM_C
#endif
#endif /* PSA_WANT_ALG_CCM */

#if defined(PSA_WANT_ALG_GCM)
#if !defined(MBEDTLS_PSA_ACCEL_ALG_GCM) || \
    defined(PSA_HAVE_SOFT_KEY_TYPE_AES) || \
    defined(PSA_HAVE_SOFT_KEY_TYPE_ARIA) || \
    defined(PSA_HAVE_SOFT_KEY_TYPE_CAMELLIA)
#define MBEDTLS_PSA_BUILTIN_ALG_GCM 1
#define MBEDTLS_GCM_C
#endif
#endif /* PSA_WANT_ALG_GCM */

#if defined(PSA_WANT_ALG_CHACHA20_POLY1305)
#if !defined(MBEDTLS_PSA_ACCEL_ALG_CHACHA20_POLY1305)
#if defined(PSA_WANT_KEY_TYPE_CHACHA20)
#define MBEDTLS_CHACHAPOLY_C
#define MBEDTLS_CHACHA20_C
#define MBEDTLS_POLY1305_C
#define MBEDTLS_PSA_BUILTIN_ALG_CHACHA20_POLY1305 1
#endif /* PSA_WANT_KEY_TYPE_CHACHA20 */
#endif /* !MBEDTLS_PSA_ACCEL_ALG_CHACHA20_POLY1305 */
#endif /* PSA_WANT_ALG_CHACHA20_POLY1305 */

#if defined(PSA_WANT_ECC_BRAINPOOL_P_R1_256)
#if !defined(MBEDTLS_PSA_ACCEL_ECC_BRAINPOOL_P_R1_256)
#define MBEDTLS_ECP_DP_BP256R1_ENABLED
#define MBEDTLS_PSA_BUILTIN_ECC_BRAINPOOL_P_R1_256 1
#endif /* !MBEDTLS_PSA_ACCEL_ECC_BRAINPOOL_P_R1_256 */
#endif /* PSA_WANT_ECC_BRAINPOOL_P_R1_256 */

#if defined(PSA_WANT_ECC_BRAINPOOL_P_R1_384)
#if !defined(MBEDTLS_PSA_ACCEL_ECC_BRAINPOOL_P_R1_384)
#define MBEDTLS_ECP_DP_BP384R1_ENABLED
#define MBEDTLS_PSA_BUILTIN_ECC_BRAINPOOL_P_R1_384 1
#endif /* !MBEDTLS_PSA_ACCEL_ECC_BRAINPOOL_P_R1_384 */
#endif /* PSA_WANT_ECC_BRAINPOOL_P_R1_384 */

#if defined(PSA_WANT_ECC_BRAINPOOL_P_R1_512)
#if !defined(MBEDTLS_PSA_ACCEL_ECC_BRAINPOOL_P_R1_512)
#define MBEDTLS_ECP_DP_BP512R1_ENABLED
#define MBEDTLS_PSA_BUILTIN_ECC_BRAINPOOL_P_R1_512 1
#endif /* !MBEDTLS_PSA_ACCEL_ECC_BRAINPOOL_P_R1_512 */
#endif /* PSA_WANT_ECC_BRAINPOOL_P_R1_512 */

#if defined(PSA_WANT_ECC_MONTGOMERY_255)
#if !defined(MBEDTLS_PSA_ACCEL_ECC_MONTGOMERY_255)
#define MBEDTLS_ECP_DP_CURVE25519_ENABLED
#define MBEDTLS_PSA_BUILTIN_ECC_MONTGOMERY_255 1
#endif /* !MBEDTLS_PSA_ACCEL_ECC_MONTGOMERY_255 */
#endif /* PSA_WANT_ECC_MONTGOMERY_255 */

#if defined(PSA_WANT_ECC_MONTGOMERY_448)
#if !defined(MBEDTLS_PSA_ACCEL_ECC_MONTGOMERY_448)
#define MBEDTLS_ECP_DP_CURVE448_ENABLED
#define MBEDTLS_PSA_BUILTIN_ECC_MONTGOMERY_448 1
#endif /* !MBEDTLS_PSA_ACCEL_ECC_MONTGOMERY_448 */
#endif /* PSA_WANT_ECC_MONTGOMERY_448 */

#if defined(PSA_WANT_ECC_SECP_R1_192)
#if !defined(MBEDTLS_PSA_ACCEL_ECC_SECP_R1_192)
#define MBEDTLS_ECP_DP_SECP192R1_ENABLED
#define MBEDTLS_PSA_BUILTIN_ECC_SECP_R1_192 1
#endif /* !MBEDTLS_PSA_ACCEL_ECC_SECP_R1_192 */
#endif /* PSA_WANT_ECC_SECP_R1_192 */

#if defined(PSA_WANT_ECC_SECP_R1_224)
#if !defined(MBEDTLS_PSA_ACCEL_ECC_SECP_R1_224)
#define MBEDTLS_ECP_DP_SECP224R1_ENABLED
#define MBEDTLS_PSA_BUILTIN_ECC_SECP_R1_224 1
#endif /* !MBEDTLS_PSA_ACCEL_ECC_SECP_R1_224 */
#endif /* PSA_WANT_ECC_SECP_R1_224 */

#if defined(PSA_WANT_ECC_SECP_R1_256)
#if !defined(MBEDTLS_PSA_ACCEL_ECC_SECP_R1_256)
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED
#define MBEDTLS_PSA_BUILTIN_ECC_SECP_R1_256 1
#endif /* !MBEDTLS_PSA_ACCEL_ECC_SECP_R1_256 */
#endif /* PSA_WANT_ECC_SECP_R1_256 */

#if defined(PSA_WANT_ECC_SECP_R1_384)
#if !defined(MBEDTLS_PSA_ACCEL_ECC_SECP_R1_384)
#define MBEDTLS_ECP_DP_SECP384R1_ENABLED
#define MBEDTLS_PSA_BUILTIN_ECC_SECP_R1_384 1
#endif /* !MBEDTLS_PSA_ACCEL_ECC_SECP_R1_384 */
#endif /* PSA_WANT_ECC_SECP_R1_384 */

#if defined(PSA_WANT_ECC_SECP_R1_521)
#if !defined(MBEDTLS_PSA_ACCEL_ECC_SECP_R1_521)
#define MBEDTLS_ECP_DP_SECP521R1_ENABLED
#define MBEDTLS_PSA_BUILTIN_ECC_SECP_R1_521 1
#endif /* !MBEDTLS_PSA_ACCEL_ECC_SECP_R1_521 */
#endif /* PSA_WANT_ECC_SECP_R1_521 */

#if defined(PSA_WANT_ECC_SECP_K1_192)
#if !defined(MBEDTLS_PSA_ACCEL_ECC_SECP_K1_192)
#define MBEDTLS_ECP_DP_SECP192K1_ENABLED
#define MBEDTLS_PSA_BUILTIN_ECC_SECP_K1_192 1
#endif /* !MBEDTLS_PSA_ACCEL_ECC_SECP_K1_192 */
#endif /* PSA_WANT_ECC_SECP_K1_192 */

#if defined(PSA_WANT_ECC_SECP_K1_224)
#if !defined(MBEDTLS_PSA_ACCEL_ECC_SECP_K1_224)
/*
 * SECP224K1 is buggy via the PSA API in Mbed TLS
 * (https://github.com/Mbed-TLS/mbedtls/issues/3541).
 */
#error "SECP224K1 is buggy via the PSA API in Mbed TLS."
#define MBEDTLS_ECP_DP_SECP224K1_ENABLED
#define MBEDTLS_PSA_BUILTIN_ECC_SECP_K1_224 1
#endif /* !MBEDTLS_PSA_ACCEL_ECC_SECP_K1_224 */
#endif /* PSA_WANT_ECC_SECP_K1_224 */

#if defined(PSA_WANT_ECC_SECP_K1_256)
#if !defined(MBEDTLS_PSA_ACCEL_ECC_SECP_K1_256)
#define MBEDTLS_ECP_DP_SECP256K1_ENABLED
#define MBEDTLS_PSA_BUILTIN_ECC_SECP_K1_256 1
#endif /* !MBEDTLS_PSA_ACCEL_ECC_SECP_K1_256 */
#endif /* PSA_WANT_ECC_SECP_K1_256 */

/**
 * \file config_psa_ext.h
 * \brief PSA crypto configurations to Mbed TLS configurations extension
 *
 *  Extension of the translation of the PSA crypto configurations to the Mbed
 *  TLS ones handling the PSA-Crypto specific configuration options.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#if defined(PSA_CRYPTO_KEY_ID_ENCODES_OWNER)
#define MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER
#endif

#if defined(PSA_CRYPTO_SPM)
#define MBEDTLS_PSA_CRYPTO_SPM
#endif

#if !defined(PSA_CRYPTO_STD_FUNCTIONS)
#include <psa/platform.h>
#define MBEDTLS_PLATFORM_C
#define MBEDTLS_PLATFORM_MEMORY
#define MBEDTLS_PLATFORM_NO_STD_FUNCTIONS
#define MBEDTLS_PLATFORM_PRINTF_MACRO  psa_crypto_printf
#define MBEDTLS_PLATFORM_FPRINTF_MACRO  psa_crypto_fprintf
#define MBEDTLS_PLATFORM_SNPRINTF_MACRO  psa_crypto_snprintf
#define MBEDTLS_PLATFORM_SETBUF_MACRO  psa_crypto_setbuf
#if defined(PSA_CRYPTO_MEMORY_BUFFER_ALLOC)
#define MBEDTLS_MEMORY_BUFFER_ALLOC_C
#define MBEDTLS_MEMORY_ALIGN_MULTIPLE 8
#else
#define MBEDTLS_PLATFORM_CALLOC_MACRO  psa_crypto_calloc
#define MBEDTLS_PLATFORM_FREE_MACRO  psa_crypto_free
#endif
#endif /* !PSA_CRYPTO_STD_FUNCTIONS */

#if defined(PSA_CRYPTO_FS_IO)
#define MBEDTLS_FS_IO
#endif

#if defined(PSA_CRYPTO_PLATFORM_ZEROIZE)
#define MBEDTLS_PLATFORM_ZEROIZE_ALT
#define mbedtls_platform_zeroize psa_crypto_platform_zeroize
#endif

#if defined(PSA_CRYPTO_BUILTIN_KEYS)
#define MBEDTLS_PSA_CRYPTO_BUILTIN_KEYS
#endif

#if defined(PSA_CRYPTO_STORAGE_C)
#define MBEDTLS_PSA_CRYPTO_STORAGE_C
#endif

#if defined(PSA_CRYPTO_ITS_FILE_C)
#define MBEDTLS_PSA_ITS_FILE_C
#endif

#if defined(PSA_CRYPTO_EXTERNAL_RNG)
#define MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG
#else /* PSA_CRYPTO_EXTERNAL_RNG */
#define MBEDTLS_ENTROPY_C

#if defined(PSA_CRYPTO_HMAC_DRBG_HASH)
#define MBEDTLS_HMAC_DRBG_C
#define MBEDTLS_MD_C

/*
 * The macro PSA_CRYPTO_HMAC_DRBG_HASH defines the hash algorithm (SHA-256 or
 * SHA-512) to be used for HMAC for the PSA DRBG. It defines it using the PSA
 * macro identifying the hash algorithm. Those macros are not part of the
 * configuration macros thus they may not be defined at that point. As we need
 * to use the value of PSA_CRYPTO_HMAC_DRBG_HASH, which is equal to
 * PSA_ALG_SHA_256 or PSA_ALG_SHA_512 we need those macros to be defined. Their
 * specific values are not important here, they just have to be different.
 */
#if !defined(PSA_ALG_SHA_256)
#define PSA_ALG_SHA_256 1
#define PSA_ALG_SHA_512 2
#define UNDEFINE_PSA_ALG_SHA_256_512
#endif

#if (PSA_CRYPTO_HMAC_DRBG_HASH == PSA_ALG_SHA_256)
#define MBEDTLS_PSA_HMAC_DRBG_MD_TYPE MBEDTLS_MD_SHA256
#if !defined(MBEDTLS_SHA256_C)
#define MBEDTLS_SHA256_C
#endif
#endif /* PSA_CRYPTO_HMAC_DRBG_HASH == PSA_ALG_SHA_256 */

#if (PSA_CRYPTO_HMAC_DRBG_HASH == PSA_ALG_SHA_512)
#if !defined(MBEDTLS_SHA512_C)
#define MBEDTLS_SHA512_C
#endif
#define MBEDTLS_PSA_HMAC_DRBG_MD_TYPE MBEDTLS_MD_SHA512
#endif /* PSA_CRYPTO_HMAC_DRBG_HASH == PSA_ALG_SHA_512 */

/* Clean-up of the dummy values for PSA_ALG_SHA_256 and PSA_ALG_SHA_512 */
#if defined(UNDEFINE_PSA_ALG_SHA_256_512)
#undef PSA_ALG_SHA_256
#undef PSA_ALG_SHA_512
#undef UNDEFINE_PSA_ALG_SHA_256_512
#endif

#else  /* PSA_CRYPTO_HMAC_DRBG_HASH */

#define MBEDTLS_CTR_DRBG_C
#if !defined(MBEDTLS_AES_C)
#define MBEDTLS_AES_C
#endif

#endif /* !PSA_CRYPTO_HMAC_DRBG_HASH */

#if !defined(PSA_CRYPTO_PLATFORM_ENTROPY)
#define MBEDTLS_NO_PLATFORM_ENTROPY
#endif

#if defined(PSA_CRYPTO_HARDWARE_ENTROPY)
#define MBEDTLS_ENTROPY_HARDWARE_ALT
#define mbedtls_hardware_poll psa_crypto_hardware_entropy
#endif

#if defined(PSA_CRYPTO_ENTROPY_NV_SEED)
#define MBEDTLS_PLATFORM_C
#define MBEDTLS_ENTROPY_NV_SEED
#if !defined(PSA_CRYPTO_STD_FUNCTIONS) || !defined(PSA_CRYPTO_FS_IO)
#include <psa/platform.h>
#define MBEDTLS_PLATFORM_NV_SEED_READ_MACRO  psa_crypto_platform_entropy_nv_seed_read
#define MBEDTLS_PLATFORM_NV_SEED_WRITE_MACRO  psa_crypto_platform_entropy_nv_seed_write
#endif
#endif /* PSA_CRYPTO_ENTROPY_NV_SEED */

#endif /* !PSA_CRYPTO_EXTERNAL_RNG */

#if defined(PSA_CRYPTO_KEY_SLOT_COUNT)
#define MBEDTLS_PSA_KEY_SLOT_COUNT PSA_CRYPTO_KEY_SLOT_COUNT
#endif

#if defined(PSA_CRYPTO_ENTROPY_NV_SEED_FILE)
#define MBEDTLS_PLATFORM_STD_NV_SEED_FILE PSA_CRYPTO_ENTROPY_NV_SEED_FILE
#endif

#endif /* MBEDTLS_PSA_CRYPTO_CONFIG */

#if defined(PSA_WANT_ALG_JPAKE)
#define PSA_WANT_ALG_SOME_PAKE 1
#endif

/* These features are always enabled. */
#define PSA_WANT_KEY_TYPE_DERIVE 1
#define PSA_WANT_KEY_TYPE_PASSWORD 1
#define PSA_WANT_KEY_TYPE_PASSWORD_HASH 1
#define PSA_WANT_KEY_TYPE_RAW_DATA 1

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_CONFIG_PSA_H */
