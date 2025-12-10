# components-configuration-crypto.sh
#
# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

# This file contains test components that are executed by all.sh

################################################################
#### Configuration Testing - Crypto
################################################################

BUILTIN_BUILD_DIR="drivers/builtin/CMakeFiles/builtin.dir/src"

support_ubuntu_version() {
    version="$(cat /etc/os-release 2>/dev/null)" || return 1
    [[ "$version" == *$1* ]]
}

component_test_accel_hash_ubuntu_16() {
    msg "test: accelerated hash Ubuntu 16"

    # Build
    # -----

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

    # Run the tests
    # -------------

    msg "test: accelerated hash"
    ctest
}

support_test_accel_hash_ubuntu_16() {
    support_ubuntu_version "Ubuntu 16"
}

component_test_accel_hash_ubuntu_22() {
    msg "test: accelerated hash Ubuntu 22"

    # Build
    # -----

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

    # Run the tests
    # -------------

    msg "test: accelerated hash"
    ctest
}

support_test_accel_hash_ubuntu_22() {
    support_ubuntu_version "Ubuntu 22"
}
