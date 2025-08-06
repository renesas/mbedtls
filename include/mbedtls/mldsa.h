/**
 * \file mldsa.h
 *
 * \brief This file provides an API for Post Quantum Cryptography Module Lattice Keys(ML_DSA).
 *
 */

/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef MBEDTLS_ML_DSA_H
#define MBEDTLS_ML_DSA_H
#include "mbedtls/private_access.h"

#include "mbedtls/build_info.h"
#include "mbedtls/platform_util.h"

#include "mbedtls/bignum.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct mbedtls_mldsa_data {
    uint32_t key_len;
    uint32_t * key_data;
} mbedtls_mldsa_data_t;

/**
 * \brief   The ML_DSA context structure.
 */
typedef struct mbedtls_mldsa_context {
    mbedtls_mldsa_data_t private_key;  /*!< The private key data. */
    mbedtls_mldsa_data_t public_key;  /*!< The public key data  */
} mbedtls_mldsa_context;

typedef enum mbedtls_mldsa_bits {
    MBEDTLS_ML_DSA_44 = 44,
    MBEDTLS_ML_DSA_65 = 65
} mbedtls_mldsa_bits_t;

void mbedtls_mldsa_init(mbedtls_mldsa_context * ctx);

int mbedtls_mldsa_generate_key(mbedtls_mldsa_context * ctx, 
                               mbedtls_mldsa_bits_t bits, 
                               uint32_t (*f_rng)(uint32_t, uint32_t *));

int mbedtls_mldsa_sign(mbedtls_mldsa_context * ctx,
                              mbedtls_mldsa_bits_t bits,
                              mbedtls_mldsa_data_t * msg,
                              mbedtls_mldsa_data_t * signature,
                              uint32_t (*f_rng)(uint32_t, uint32_t *));

int mbedtls_mldsa_verify(mbedtls_mldsa_context * ctx,
                              mbedtls_mldsa_bits_t bits,
                              mbedtls_mldsa_data_t * signature,
                              mbedtls_mldsa_data_t * msg);

#ifdef __cplusplus
}
#endif

#endif /* mldsa.h */