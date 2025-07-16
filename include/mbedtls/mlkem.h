/**
 * \file mlkem.h
 *
 * \brief This file provides an API for Elliptic Curves over GF(P) (MLKEM).
 *
 * The use of MLKEM in cryptography and TLS is defined in
 * <em>Standards for Efficient Cryptography Group (SECG): SEC1
 * Elliptic Curve Cryptography</em> and
 * <em>RFC-4492: Elliptic Curve Cryptography (ECC) Cipher Suites
 * for Transport Layer Security (TLS)</em>.
 *
 * <em>RFC-2409: The Internet Key Exchange (IKE)</em> defines MLKEM
 * group types.
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

#include "r_pqc_api.h"

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
    mbedtls_mlkem_data_t cipher;      /*!< The cipher data. */
    mbedtls_mlkem_data_t shared_key;  /*!< The shared key data. */
    uint32_t * p_buf;               /*!< Pointer to the buffer used for internal operations. */
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
                              uint32_t (*f_rng)(uint32_t, uint32_t *));

int mbedtls_mlkem_decapsulate(mbedtls_mlkem_context * ctx,
                              mbedtls_mlkem_bits_t bits,
                              uint32_t (*f_rng)(uint32_t, uint32_t *));

#ifdef __cplusplus
}
#endif

#endif /* mlkem.h */