/**
 * \file mldsa.h
 *
 * \brief This file provides an API for Post Quantum Cryptography Module Lattice Keys (ML_DSA).
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
#include "mbedtls/md.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief  Structure to hold key or seed data for ML_DSA operations.
 *         Contains the length of the data and a pointer to the data buffer.
 */
typedef struct mbedtls_mldsa_data {
    uint32_t len;
    uint32_t * p_data;
} mbedtls_mldsa_data_t;

/**
 * \brief   The ML_DSA context structure.
 */
typedef struct mbedtls_mldsa_context {
    mbedtls_mldsa_data_t private_key;  /*!< The private key data. */
    mbedtls_mldsa_data_t public_key;   /*!< The public key data  */
    mbedtls_mldsa_data_t seed;         /*!< Seed key data  */
} mbedtls_mldsa_context;

/**
 * \brief  Enumeration of supported ML_DSA parameter sets, indicating the security level in bits.
 *         - MBEDTLS_ML_DSA_44: 44-bit security level.
 *         - MBEDTLS_ML_DSA_65: 65-bit security level.
 */
typedef enum mbedtls_mldsa_bits {
    MBEDTLS_ML_DSA_44 = 44,
    MBEDTLS_ML_DSA_65 = 65,
    MBEDTLS_ML_DSA_87 = 87
} mbedtls_mldsa_bits_t;

/**
 * @brief Initialize an ML-DSA context.
 *
 * @param ctx Pointer to the ML-DSA context to initialize.
 */
void mbedtls_mldsa_init(mbedtls_mldsa_context * ctx);

/**
 * @brief Export the keypair from the ML-DSA context.
 *
 * @param ctx Pointer to the ML-DSA context.
 * @param key_buffer Buffer to hold the exported keypair.
 * @param key_buffer_length Pointer to the length of the key buffer. Will be updated with the actual length.
 *
 * @return 0 on success, or a negative error code.
 */
int mbedtls_mldsa_export_keypair(mbedtls_mldsa_context * ctx,
                                 uint8_t * key_buffer,
                                 size_t * key_buffer_length);

/**
 * @brief Export the public key from the ML-DSA context.
 *
 * @param ctx Pointer to the ML-DSA context.
 * @param bits Security parameter specifying the key size.
 *
 * @return 0 on success, or a negative error code.
 */
int mbedtls_mldsa_export_public_key(mbedtls_mldsa_context * ctx,
                                    uint8_t * key_buffer,
                                    size_t * key_buffer_length);

/**
 * @brief Expand a key pair using provided random values.
 *
 * @param ctx Pointer to the ML-DSA context.
 * @param bits Security parameter specifying the key size.
 * @param seed Pointer to random data seed.
 * @param f_rng Random number generator function.
 *
 * @return 0 on success, or a negative error code.
 */
int mbedtls_mldsa_expand_key_pair(mbedtls_mldsa_context *ctx,
                                  mbedtls_mldsa_bits_t bits,
                                  mbedtls_mldsa_data_t *seed,
                                  uint32_t (*f_rng)(uint32_t, uint32_t *));

/**
 * @brief Generate a new ML-DSA key pair.
 *
 * @param ctx Pointer to the ML-DSA context.
 * @param bits Security parameter specifying the key size.
 * @param f_rng Random number generator function.
 *
 * @return 0 on success, or a negative error code.
 */
int mbedtls_mldsa_generate_key(mbedtls_mldsa_context * ctx, 
                               mbedtls_mldsa_bits_t bits, 
                               uint32_t (*f_rng)(uint32_t, uint32_t *));

/**
 * @brief Generate ML-DSA signature from a previously-hashed message.
 *
 * @param ctx Pointer to the ML-DSA context.
 * @param bits Security parameter specifying the key size.
 * @param md_alg Message digest algorithm to use.
 * @param hash Pointer to message digest buffer
 * @param signature Pointer to signature buffer
 * @param f_rng Random number generator function.
 *
 * @return 0 on success, or a negative error code.
 */
int mbedtls_mldsa_sign(mbedtls_mldsa_context * ctx,
                       mbedtls_mldsa_bits_t bits,
                       mbedtls_md_type_t md_alg,
                       mbedtls_mldsa_data_t * hash,
                       mbedtls_mldsa_data_t * signature,
                       uint32_t (*f_rng)(uint32_t, uint32_t *));

/**
 * @brief Verify ML-DSA signature from a previously-hashed message.
 *
 * @param ctx Pointer to the ML-DSA context.
 * @param bits Security parameter specifying the key size.
 * @param md_alg Message digest algorithm to use.
 * @param msg Pointer to message digest buffer
 * @param signature Pointer to signature buffer
 * @param f_rng Random number generator function.
 *
 * @return 0 on success, or a negative error code.
 */
int mbedtls_mldsa_verify(mbedtls_mldsa_context * ctx,
                         mbedtls_mldsa_bits_t bits,
                         mbedtls_md_type_t md_alg,
                         mbedtls_mldsa_data_t * signature,
                         mbedtls_mldsa_data_t * msg,
                         uint32_t (*f_rng)(uint32_t, uint32_t *));

#ifdef __cplusplus
}
#endif

#endif /* mldsa.h */