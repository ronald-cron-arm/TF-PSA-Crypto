/**
 * \file build_info.h
 *
 * \brief Build-time configuration info
 *
 *  Include this file if you need to depend on the
 *  configuration options defined in crypto_config.h or TF_PSA_CRYPTO_CONFIG_FILE.
 */
 /*
  *  Copyright The Mbed TLS Contributors
  *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
  */

#ifndef TF_PSA_CRYPTO_BUILD_INFO_H
#define TF_PSA_CRYPTO_BUILD_INFO_H

#include <tf_psa_crypto/version.h>

#define STRINGIFY_(x) #x
#define STRINGIFY(x) STRINGIFY_(x)

/**
 * The single version number has the following structure:
 *    MMNNPP00
 *    Major version | Minor version | Patch version
 */
#define TF_PSA_CRYPTO_VERSION_NUMBER  ((TF_PSA_CRYPTO_VERSION_MAJOR << 24) | \
                                       (TF_PSA_CRYPTO_VERSION_MINOR << 16) | \
                                       (TF_PSA_CRYPTO_VERSION_PATCH <<  8))

#define TF_PSA_CRYPTO_VERSION_STRING  STRINGIFY(TF_PSA_CRYPTO_VERSION_MAJOR) \
                                                   "."                       \
                                      STRINGIFY(TF_PSA_CRYPTO_VERSION_MINOR) \
                                                   "."                       \
                                      STRINGIFY(TF_PSA_CRYPTO_VERSION_PATCH)
#define TF_PSA_CRYPTO_VERSION_STRING_FULL  ("TF-PSA-Crypto " TF_PSA_CRYPTO_VERSION_STRING)

/* Macros for build-time platform detection */

#if !defined(MBEDTLS_ARCH_IS_ARM64) && \
    (defined(__aarch64__) || defined(_M_ARM64) || defined(_M_ARM64EC))
#define MBEDTLS_ARCH_IS_ARM64
#endif

#if !defined(MBEDTLS_ARCH_IS_ARM32) && \
    (defined(__arm__) || defined(_M_ARM) || \
    defined(_M_ARMT) || defined(__thumb__) || defined(__thumb2__))
#define MBEDTLS_ARCH_IS_ARM32
#endif

#if !defined(MBEDTLS_ARCH_IS_X64) && \
    (defined(__amd64__) || defined(__x86_64__) || \
    ((defined(_M_X64) || defined(_M_AMD64)) && !defined(_M_ARM64EC)))
#define MBEDTLS_ARCH_IS_X64
#endif

#if !defined(MBEDTLS_ARCH_IS_X86) && \
    (defined(__i386__) || defined(_X86_) || \
    (defined(_M_IX86) && !defined(_M_I86)))
#define MBEDTLS_ARCH_IS_X86
#endif

#if !defined(MBEDTLS_PLATFORM_IS_WINDOWS_ON_ARM64) && \
    (defined(_M_ARM64) || defined(_M_ARM64EC))
#define MBEDTLS_PLATFORM_IS_WINDOWS_ON_ARM64
#endif

/* This is defined if the architecture is Armv8-A, or higher */
#if !defined(MBEDTLS_ARCH_IS_ARMV8_A)
#if defined(__ARM_ARCH) && defined(__ARM_ARCH_PROFILE)
#if (__ARM_ARCH >= 8) && (__ARM_ARCH_PROFILE == 'A')
/* GCC, clang, armclang and IAR */
#define MBEDTLS_ARCH_IS_ARMV8_A
#endif
#elif defined(__ARM_ARCH_8A)
/* Alternative defined by clang */
#define MBEDTLS_ARCH_IS_ARMV8_A
#elif defined(_M_ARM64) || defined(_M_ARM64EC)
/* MSVC ARM64 is at least Armv8.0-A */
#define MBEDTLS_ARCH_IS_ARMV8_A
#endif
#endif

#if defined(__GNUC__) && !defined(__ARMCC_VERSION) && !defined(__clang__) \
    && !defined(__llvm__) && !defined(__INTEL_COMPILER)
/* Defined if the compiler really is gcc and not clang, etc */
#define MBEDTLS_COMPILER_IS_GCC
#define MBEDTLS_GCC_VERSION \
    (__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__)
#endif

#if defined(_MSC_VER) && !defined(_CRT_SECURE_NO_DEPRECATE)
#define _CRT_SECURE_NO_DEPRECATE 1
#endif

/* Define `inline` on some non-C99-compliant compilers. */
#if ( defined(__ARMCC_VERSION) || defined(_MSC_VER) ) && \
    !defined(inline) && !defined(__cplusplus)
#define inline __inline
#endif

/*
 * Configuration of the PSA cryptographic mechanisms to include in the PSA
 * cryptography interface.
 */
#if !defined(TF_PSA_CRYPTO_CONFIG_FILE)
#include "psa/crypto_config.h"
#else
#include TF_PSA_CRYPTO_CONFIG_FILE
#endif

/*
 * Patch the configuration defined by `"psa/crypto_config.h"` or
 * #TF_PSA_CRYPTO_CONFIG_FILE.
 */
#if defined(TF_PSA_CRYPTO_CONFIG_PATCH)
#include TF_PSA_CRYPTO_CONFIG_PATCH
#endif

/*
 * Compute Mbed TLS configuration options from the TF-PSA-Crypto ones as
 * PSA headers and core depends on some of them.
 */
#define MBEDTLS_PSA_CRYPTO_C
#define MBEDTLS_PSA_CRYPTO_CONFIG
#include "mbedtls/config_psa.h"

#include "mbedtls/config_adjust_legacy_crypto.h"

#endif /* TF_PSA_CRYPTO_BUILD_INFO_H */
