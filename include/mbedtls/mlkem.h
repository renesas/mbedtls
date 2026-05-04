/**
 * \file mlkem.h
 *
 * \brief   This file contains the definition of data structures, enumerations, and APIs
 *          for MLKEM (Module-Lattice Key Encapsulation Mechanism) support in mbedtls.
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

/**
 * \brief  Structure to hold key or seed data for MLKEM operations.
 *         Contains the length of the data and a pointer to the data buffer.
 */
typedef struct mbedtls_mlkem_data {
    uint32_t key_len;
    uint32_t * key_data;
} mbedtls_mlkem_data_t;

/**
 * \brief  MLKEM context structure holding all necessary key and seed data for
 *         encapsulation and decapsulation operations.
 */
typedef struct mbedtls_mlkem_context {
    mbedtls_mlkem_data_t decaps_key;    /*!< The decapsulated key data  */
    mbedtls_mlkem_data_t d;             /*!< d seed data. */
    mbedtls_mlkem_data_t z;             /*!< z seed data. */
    mbedtls_mlkem_data_t encaps_key;    /*!< The encapsulated key data  */
} mbedtls_mlkem_context;

/**
 * \brief  Enumeration of supported MLKEM parameter sets, indicating the security level in bits.
 *         - MBEDTLS_MLKEM_512: 512-bit security level.
 *         - MBEDTLS_MLKEM_768: 768-bit security level.
 */
typedef enum mbedtls_mlkem_bits {
    MBEDTLS_MLKEM_512 = 512,
    MBEDTLS_MLKEM_768 = 768,
    MBEDTLS_MLKEM_1024 = 1024
} mbedtls_mlkem_bits_t;

/**
 * @brief Initialize an ML-KEM context.
 *
 * @param ctx Pointer to the ML-KEM context to initialize.
 */
void mbedtls_mlkem_init(mbedtls_mlkem_context * ctx);

/**
 * @brief Export the keypair from the ML-KEM context.
 *
 * @param ctx Pointer to the ML-KEM context.
 * @param key_buffer Buffer to hold the exported keypair.
 * @param key_buffer_length Pointer to the length of the key buffer. Will be updated with the actual length.
 *
 * @return 0 on success, or a negative error code.
 */
int mbedtls_mlkem_export_keypair(mbedtls_mlkem_context * ctx,
                                 uint8_t * key_buffer,
                                 size_t * key_buffer_length);

/**
 * @brief Export the public key from the ML-KEM context.
 *
 * @param ctx Pointer to the ML-KEM context.
 * @param bits Security parameter specifying the key size.
 *
 * @return 0 on success, or a negative error code.
 */
int mbedtls_mlkem_export_public_key(mbedtls_mlkem_context * ctx,
                                    mbedtls_mlkem_bits_t bits);

/**
 * @brief Expand a key pair using provided random values.
 *
 * @param ctx Pointer to the ML-KEM context.
 * @param bits Security parameter specifying the key size.
 * @param random_d Pointer to random data D.
 * @param random_z Pointer to random data Z.
 * @param f_rng Random number generator function.
 *
 * @return 0 on success, or a negative error code.
 */
int mbedtls_mlkem_expand_key_pair(mbedtls_mlkem_context *ctx,
                               mbedtls_mlkem_bits_t bits,
                               mbedtls_mlkem_data_t *random_d,
                               mbedtls_mlkem_data_t *random_z,
                               uint32_t (*f_rng)(uint32_t, uint32_t *));

/**
 * @brief Generate a new ML-KEM key pair.
 *
 * @param ctx Pointer to the ML-KEM context.
 * @param bits Security parameter specifying the key size.
 * @param f_rng Random number generator function.
 *
 * @return 0 on success, or a negative error code.
 */
int mbedtls_mlkem_generate_key(mbedtls_mlkem_context * ctx, 
                               mbedtls_mlkem_bits_t bits,
                               uint32_t (*f_rng)(uint32_t, uint32_t *));

/**
 * @brief Encapsulate a shared key using the ML-KEM context.
 *
 * @param ctx Pointer to the ML-KEM context.
 * @param bits Security parameter specifying the key size.
 * @param cipher Pointer to the output cipher data.
 * @param shared_key Pointer to the output shared key data.
 * @param f_rng Random number generator function.
 *
 * @return 0 on success, or a negative error code.
 */
int mbedtls_mlkem_encapsulate(mbedtls_mlkem_context * ctx,
                              mbedtls_mlkem_bits_t bits,
                              mbedtls_mlkem_data_t * cipher,
                              mbedtls_mlkem_data_t * shared_key,
                              uint32_t (*f_rng)(uint32_t, uint32_t *));

/**
 * @brief Decapsulate a shared key using the ML-KEM context.
 *
 * @param ctx Pointer to the ML-KEM context.
 * @param bits Security parameter specifying the key size.
 * @param cipher Pointer to the input cipher data.
 * @param shared_key Pointer to the output shared key data.
 * @param f_rng Random number generator function.
 *
 * @return 0 on success, or a negative error code.
 */
int mbedtls_mlkem_decapsulate(mbedtls_mlkem_context * ctx,
                              mbedtls_mlkem_bits_t bits,
                              mbedtls_mlkem_data_t * cipher,
                              mbedtls_mlkem_data_t * shared_key,
                              uint32_t (*f_rng)(uint32_t, uint32_t *));

#ifdef __cplusplus
}
#endif

#endif /* mlkem.h */