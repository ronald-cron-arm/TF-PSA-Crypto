# components-configuration-crypto.sh
#
# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

# This file contains test components that are executed by all.sh

################################################################
#### Configuration Testing - Crypto
################################################################

BUILTIN_BUILD_DIR="drivers/builtin/CMakeFiles/builtin.dir/src"

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
