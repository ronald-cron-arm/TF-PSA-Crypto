# components-configuration-crypto.sh
#
# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

# This file contains test components that are executed by all.sh

################################################################
#### Configuration Testing - Crypto
################################################################

export BUILTIN_BUILD_DIR="drivers/builtin/CMakeFiles/builtin.dir/src"

component_test_accel_all_ecc () {
    msg "build: full + all ECC accelerated"

    # Configure
    # ---------
    ./scripts/config.py full
    # Disable all the features that auto-enable ECP_LIGHT (see build_info.h)
    scripts/config.py unset MBEDTLS_PK_PARSE_EC_EXTENDED
    scripts/config.py unset MBEDTLS_PK_PARSE_EC_COMPRESSED
    scripts/config.py unset PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_DERIVE

    # Restartable feature is not yet supported by PSA. Once it will in
    # the future, the following line could be removed (see issues
    # 6061, 6332 and following ones)
    scripts/config.py unset MBEDTLS_ECP_RESTARTABLE

    # Build
    # -----
    cd $OUT_OF_SOURCE_DIR
    cmake -DTF_PSA_CRYPTO_TEST_DRIVER=On \
          -DTF_PSA_CRYPTO_USER_CONFIG_FILE="../tests/configs/user-config-accel-all-ecc.h" ..
    make

    # Make sure any built-in EC alg was not re-enabled by accident (additive config)
    not grep mbedtls_ecdsa_ ${BUILTIN_BUILD_DIR}/ecdsa.c.o
    not grep mbedtls_ecdh_ ${BUILTIN_BUILD_DIR}/ecdh.c.o
    not grep mbedtls_ecjpake_ ${BUILTIN_BUILD_DIR}/ecjpake.c.o
    # Also ensure that ECP module was not re-enabled
    not grep mbedtls_ecp_ ${BUILTIN_BUILD_DIR}/ecp.c.o

    # Run the tests
    # -------------

    msg "test: full + all ECC accelerated"
    ctest
}

component_test_accel_aead () {
    msg "test: accelerated AEAD"

    # Configure
    # ---------
    ./scripts/config.py full
    # Disable CCM_STAR_NO_TAG because this re-enables CCM_C.
    scripts/config.py unset PSA_WANT_ALG_CCM_STAR_NO_TAG

    # Build
    # -----
    cd $OUT_OF_SOURCE_DIR
    cmake -DTF_PSA_CRYPTO_TEST_DRIVER=On \
          -DTF_PSA_CRYPTO_USER_CONFIG_FILE="../tests/configs/user-config-accel-aead.h" ..
    make

    # Make sure this was not re-enabled by accident (additive config)
    not grep mbedtls_ccm ${BUILTIN_BUILD_DIR}/ccm.c.o
    not grep mbedtls_gcm ${BUILTIN_BUILD_DIR}/gcm.c.o
    not grep mbedtls_chachapoly ${BUILTIN_BUILD_DIR}/chachapoly.c.o

    # Run the tests
    # -------------

    msg "test: accelerated AEAD"
    ctest
}

component_test_accel_cipher_aead_cmac () {
    msg "build: full config with accelerated cipher inc. AEAD and CMAC"

    loc_accel_list="ALG_ECB_NO_PADDING ALG_CBC_NO_PADDING ALG_CBC_PKCS7 ALG_CTR ALG_CFB \
                    ALG_OFB ALG_XTS ALG_STREAM_CIPHER ALG_CCM_STAR_NO_TAG \
                    ALG_GCM ALG_CCM ALG_CHACHA20_POLY1305 ALG_CMAC \
                    KEY_TYPE_AES KEY_TYPE_ARIA KEY_TYPE_CHACHA20 KEY_TYPE_CAMELLIA"

    # Configure
    # ---------

    ./scripts/config.py full
    scripts/config.py unset MBEDTLS_NIST_KW_C

    # Build
    # -----

    cd $OUT_OF_SOURCE_DIR
    cmake -DTF_PSA_CRYPTO_TEST_DRIVER=On \
          -DTF_PSA_CRYPTO_USER_CONFIG_FILE="../tests/configs/user-config-accel-cipher-aead-cmac.h" ..
    make

    # Make sure this was not re-enabled by accident (additive config)
    not grep mbedtls_cipher ${BUILTIN_BUILD_DIR}/cipher.c.o
    not grep mbedtls_aes ${BUILTIN_BUILD_DIR}/aes.c.o
    not grep mbedtls_aria ${BUILTIN_BUILD_DIR}/aria.c.o
    not grep mbedtls_camellia ${BUILTIN_BUILD_DIR}/camellia.c.o
    not grep mbedtls_ccm ${BUILTIN_BUILD_DIR}/ccm.c.o
    not grep mbedtls_gcm ${BUILTIN_BUILD_DIR}/gcm.c.o
    not grep mbedtls_chachapoly ${BUILTIN_BUILD_DIR}/chachapoly.c.o
    not grep mbedtls_cmac ${BUILTIN_BUILD_DIR}/cmac.c.o
    not grep mbedtls_poly1305 ${BUILTIN_BUILD_DIR}/poly1305.c.o

    # Run the tests
    # -------------

    msg "test: full config with accelerated cipher inc. AEAD and CMAC"
    ctest
}

component_test_accel_ffdh () {
    msg "build: full with accelerated FFDH"

    # Configure
    # ---------

    ./scripts/config.py full

    # Build
    # -----

    cd $OUT_OF_SOURCE_DIR
    cmake -DTF_PSA_CRYPTO_TEST_DRIVER=On \
          -DTF_PSA_CRYPTO_USER_CONFIG_FILE="../tests/configs/user-config-accel-ffdh.h" ..
    make

    # Make sure this was not re-enabled by accident (additive config)
    not grep mbedtls_psa_ffdh_key_agreement ${BUILTIN_BUILD_DIR}/psa_crypto_ffdh.c.o

    # Run the tests
    # -------------

    msg "test: full with accelerated FFDH"
    ctest
}

component_test_accel_hash () {
    msg "test: accelerated hash"
    cd $OUT_OF_SOURCE_DIR

    cmake -DTF_PSA_CRYPTO_TEST_DRIVER=On \
          -DTF_PSA_CRYPTO_USER_CONFIG_FILE="../tests/configs/user-config-accel-hash.h" ..
    make

    # Make sure built-in hash objects are empty.
    not grep mbedtls_md5 ${BUILTIN_BUILD_DIR}/md5.c.o
    not grep mbedtls_sha1 ${BUILTIN_BUILD_DIR}/sha1.c.o
    not grep mbedtls_sha256 ${BUILTIN_BUILD_DIR}/sha256.c.o
    not grep mbedtls_sha512 ${BUILTIN_BUILD_DIR}/sha512.c.o
    not grep mbedtls_ripemd160 ${BUILTIN_BUILD_DIR}/ripemd160.c.o

    msg "test: accelerated hash"
    ctest
}

component_test_accel_hmac () {
    msg "test: full with accelerated hmac"

    # Configure
    # ---------

    ./scripts/config.py full

    # Disable MD_C in order to disable the builtin support for HMAC. MD_LIGHT
    # is still enabled though (for ENTROPY_C among others).
    scripts/config.py unset MBEDTLS_MD_C

    # Direct dependencies of MD_C. We disable them also in the reference
    # component to work with the same set of features.
    scripts/config.py unset MBEDTLS_PKCS7_C
    scripts/config.py unset MBEDTLS_PKCS5_C
    scripts/config.py unset MBEDTLS_HMAC_DRBG_C
    scripts/config.py unset MBEDTLS_HKDF_C
    # Dependencies of HMAC_DRBG
    scripts/config.py unset PSA_WANT_ALG_DETERMINISTIC_ECDSA
    # Dependencies of built-in SHA-512
    scripts/config.py unset-all "MBEDTLS_SHA512_USE_A64_CRYPTO_*"
    scripts/config.py unset-all "MBEDTLS_SHA256_USE_ARMV8_A_CRYPTO_*"

    # Build
    # -----

    cd $OUT_OF_SOURCE_DIR
    cmake -DTF_PSA_CRYPTO_TEST_DRIVER=On \
          -DTF_PSA_CRYPTO_USER_CONFIG_FILE="../tests/configs/user-config-accel-hmac.h" ..
    make

    # Ensure that built-in support for HMAC is disabled.
    not grep mbedtls_md_hmac ${BUILTIN_SRC_PATH}/md.c.o

    # Run the tests
    # -------------

    msg "test: full with accelerated hmac"
    ctest
}

component_test_accel_ecdsa() {
    msg "build: accelerated ECDSA"
    cd $OUT_OF_SOURCE_DIR

    cmake -DTF_PSA_CRYPTO_TEST_DRIVER=On \
          -DTF_PSA_CRYPTO_USER_CONFIG_FILE="../tests/configs/user-config-accel-ecdsa.h" ..
    make

    # Make sure built-in ECDSA was not re-enabled by accident (additive config)
    not grep mbedtls_ecdsa_ ${BUILTIN_BUILD_DIR}/ecdsa.c.o

    msg "test: accelerated ECDSA"
    ctest
}

component_test_accel_ecdh() {
    msg "build: accelerated ECDH"
    cd $OUT_OF_SOURCE_DIR

    cmake -DTF_PSA_CRYPTO_TEST_DRIVER=On \
          -DTF_PSA_CRYPTO_USER_CONFIG_FILE="../tests/configs/user-config-accel-ecdh.h" ..
    make

    # Make sure built-in ECDH was not re-enabled by accident (additive config)
    not grep mbedtls_ecdh_ ${BUILTIN_BUILD_DIR}/ecdh.c.o

    msg "test: accelerated ECDH"
    ctest
}

component_test_accel_jpake() {
    msg "build: full with accelerated JPAKE"
    ./scripts/config.py full
    cd $OUT_OF_SOURCE_DIR

    cmake -DTF_PSA_CRYPTO_TEST_DRIVER=On \
          -DTF_PSA_CRYPTO_USER_CONFIG_FILE="../tests/configs/user-config-accel-jpake.h" ..
    make

    # Make sure built-in ECDH was not re-enabled by accident (additive config)
    not grep mbedtls_ecjpake_init ${BUILTIN_BUILD_DIR}/ecjpake.c.o

    msg "test: full with accelerated JPAKE"
    ctest
}

component_test_accel_ecc_some_key_types () {
    msg "build: full with accelerated EC algs and some key types"
    ./scripts/config.py full

    # Restartable feature is not yet supported by PSA. Once it will in
    # the future, the following line could be removed (see issues
    # 6061, 6332 and following ones)
    scripts/config.py unset MBEDTLS_ECP_RESTARTABLE

    cd $OUT_OF_SOURCE_DIR

    cmake -DTF_PSA_CRYPTO_TEST_DRIVER=On \
          -DTF_PSA_CRYPTO_USER_CONFIG_FILE="../tests/configs/user-config-accel-ecc-some-key-types.h" ..
    make

    # ECP should be enabled but not the others
    not grep mbedtls_ecdh ${BUILTIN_BUILD_DIR}/ecdh.c.o
    not grep mbedtls_ecdsa ${BUILTIN_BUILD_DIR}/ecdsa.c.o
    not grep mbedtls_ecjpake  ${BUILTIN_BUILD_DIR}/ecjpake.c.o
    grep mbedtls_ecp ${BUILTIN_BUILD_DIR}/ecp.c.o

    msg "test suites: full with accelerated EC algs and some key types"
    ctest
}

# Run tests with only (non-)Weierstrass accelerated
# Common code used in:
# - component_test_accel_ecc_weierstrass_curves
# - component_test_accel_ecc_non_weierstrass_curves
common_test_accel_ecc_some_curves () {
    weierstrass=$1
    if [ $weierstrass -eq 1 ]; then
        desc="Weierstrass"
    else
        desc="non-Weierstrass"
    fi
    msg "build: full minus PK with accelerated EC algs and $desc curves"

    # Configure
    # ---------

    # Start with config crypto_full and remove PK_C:
    # that's what's supported now, see docs/driver-only-builds.md.
    ./scripts/config.py full
    scripts/config.py unset MBEDTLS_PK_C
    scripts/config.py unset MBEDTLS_PK_PARSE_C
    scripts/config.py unset MBEDTLS_PK_WRITE_C

    # Restartable feature is not yet supported by PSA. Once it will in
    # the future, the following line could be removed (see issues
    # 6061, 6332 and following ones)
    scripts/config.py unset MBEDTLS_ECP_RESTARTABLE

    # this is not supported by the driver API yet
    scripts/config.py unset PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_DERIVE

    scripts/config.py -f "tests/configs/user-config-accel-all-ecc.h" \
                      unset-all MBEDTLS_PSA_ACCEL_ECC_

    if [ $weierstrass -eq 1 ]; then
        scripts/config.py -f "tests/configs/user-config-accel-all-ecc.h" \
                          set-all MBEDTLS_PSA_ACCEL_ECC_SECP
        scripts/config.py -f "tests/configs/user-config-accel-all-ecc.h" \
                          set-all MBEDTLS_PSA_ACCEL_ECC_BRAINPOOL
    else
        scripts/config.py -f "tests/configs/user-config-accel-all-ecc.h" \
                          set-all MBEDTLS_PSA_ACCEL_ECC_MONTGOMERY
    fi

    cat "tests/configs/user-config-accel-all-ecc.h"

    # Build
    # -----
    cd $OUT_OF_SOURCE_DIR
    cmake -DTF_PSA_CRYPTO_TEST_DRIVER=On \
          -DTF_PSA_CRYPTO_USER_CONFIG_FILE="../tests/configs/user-config-accel-all-ecc.h" ..
    make

    # We expect ECDH to be re-enabled for the missing curves
    grep mbedtls_ecdh_ ${BUILTIN_BUILD_DIR}/ecdh.c.o
    # We expect ECP to be re-enabled, however the parts specific to the
    # families of curves that are accelerated should be ommited.
    # - functions with mxz in the name are specific to Montgomery curves
    # - ecp_muladd is specific to Weierstrass curves
    ##nm ${BUILTIN_SRC_PATH}/ecp.o | tee ecp.syms
    if [ $weierstrass -eq 1 ]; then
        not grep mbedtls_ecp_muladd ${BUILTIN_BUILD_DIR}/ecp.c.o
        grep mxz ${BUILTIN_BUILD_DIR}/ecp.c.o
    else
        grep mbedtls_ecp_muladd ${BUILTIN_BUILD_DIR}/ecp.c.o
        not grep mxz ${BUILTIN_BUILD_DIR}/ecp.c.o
    fi
    # We expect ECDSA and ECJPAKE to be re-enabled only when
    # Weierstrass curves are not accelerated
    if [ $weierstrass -eq 1 ]; then
        not grep mbedtls_ecdsa ${BUILTIN_BUILD_DIR}/ecdsa.c.o
        not grep mbedtls_ecjpake  ${BUILTIN_BUILD_DIR}/ecjpake.c.o
    else
        grep mbedtls_ecdsa ${BUILTIN_BUILD_DIR}/ecdsa.c.o
        grep mbedtls_ecjpake  ${BUILTIN_BUILD_DIR}/ecjpake.c.o
    fi

    # Run the tests
    # -------------

    msg "test suites: crypto_full minus PK with accelerated EC algs and weirstrass curves"
    ctest
}

component_test_accel_ecc_weierstrass_curves () {
    common_test_accel_ecc_some_curves 1
}

component_test_accel_ecc_non_weierstrass_curves () {
    common_test_accel_ecc_some_curves 0
}

component_test_accel_rsa() {
    msg "build: accelerated RSA"

    ./scripts/config.py full

    cd $OUT_OF_SOURCE_DIR

    cmake -DTF_PSA_CRYPTO_TEST_DRIVER=On \
          -DTF_PSA_CRYPTO_USER_CONFIG_FILE="../tests/configs/user-config-accel-rsa.h" ..
    make

    # Make sure built-in RSA was not re-enabled by accident (additive config)
    not grep mbedtls_ecdh_ ${BUILTIN_BUILD_DIR}/rsa.c.o

    msg "test: accelerated RSA"
    ctest
}
