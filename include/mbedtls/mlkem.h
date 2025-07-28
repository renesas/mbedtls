/**
 * \file mlkem.h
 *
 * \brief This file provides an API for Post Quantum Cryptography Module Lattice Keys(MLKEM).
 *
 */

/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef MBEDTLS_MLKEM_H
#define MBEDTLS_MLKEM_H
#include "mbedtls/private_access.h"

#include "mbedtls/build_info.h"
#include "mbedtls/platform_util.h"

#include "mbedtls/bignum.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct mbedtls_mlkem_data {
    uint32_t key_len;
    uint32_t * key_data;
} mbedtls_mlkem_data_t;

/**
 * \brief   The MLKEM context structure.
 */
typedef struct mbedtls_mlkem_context {
    mbedtls_mlkem_data_t encaps_key;  /*!< The encapsulated key data. */
    mbedtls_mlkem_data_t decaps_key;  /*!< The decapsulated key data  */
} mbedtls_mlkem_context;

typedef enum mbedtls_mlkem_bits {
    MBEDTLS_MLKEM_512 = 512,
    MBEDTLS_MLKEM_768 = 768
} mbedtls_mlkem_bits_t;

void mbedtls_mlkem_init(mbedtls_mlkem_context * ctx);

int mbedtls_mlkem_generate_key(mbedtls_mlkem_context * ctx, 
                               mbedtls_mlkem_bits_t bits,
                               uint32_t (*f_rng)(uint32_t, uint32_t *));

int mbedtls_mlkem_encapsulate(mbedtls_mlkem_context * ctx,
                              mbedtls_mlkem_bits_t bits,
                              mbedtls_mlkem_data_t * cipher,
                              mbedtls_mlkem_data_t * shared_key,
                              uint32_t (*f_rng)(uint32_t, uint32_t *));

int mbedtls_mlkem_decapsulate(mbedtls_mlkem_context * ctx,
                              mbedtls_mlkem_bits_t bits,
                              mbedtls_mlkem_data_t * cipher,
                              mbedtls_mlkem_data_t * shared_key,
                              uint32_t (*f_rng)(uint32_t, uint32_t *));

#ifdef __cplusplus
}
#endif

#endif /* mlkem.h */