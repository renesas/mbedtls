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

typedef struct mbedtls_mlkem_keydata {
    uint32_t key_len;
    uint32_t * key_data;
} mbedtls_mlkem_keydata;

/**
 * \brief   The MLKEM context structure.
 */
typedef struct mbedtls_mlkem_context {
    // st_pqc_mlkem_ctx_t* pqc_ctx; /*!< Pointer to the PQC MLKEM context. */
    mbedtls_mlkem_keydata encaps_key;  /*!< The encapsulated key data. */
    mbedtls_mlkem_keydata decaps_key;  /*!< The decapsulated key data  */

} mbedtls_mlkem_context;

typedef enum mbedtls_mlkem_bits {
    MBEDTLS_MLKEM_512 = 512,
    MBEDTLS_MLKEM_768 = 768
} mbedtls_mlkem_bits;

void mbedtls_mlkem_init(mbedtls_mlkem_context * ctx);

int mbedtls_mlkem_generate_key(mbedtls_mlkem_context * ctx, 
                               mbedtls_mlkem_bits bits,
                               uint32_t (*f_rng)(uint32_t, uint32_t *));

#ifdef __cplusplus
}
#endif

#endif /* mlkem.h */