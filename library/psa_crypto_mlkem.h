/*
 *  PSA MLKEM layer on top of Mbed TLS crypto
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef PSA_CRYPTO_MLKEM_H
#define PSA_CRYPTO_MLKEM_H

#include <psa/crypto.h>
#include <mbedtls/mlkem.h>

/**
 * \brief Generate an MLKEM key.
 *
 * \note The signature of the function is that of a PSA driver generate_key
 *       entry point.
 *
 * \param[in]  attributes         The attributes for the MLKEM key to generate.
 * \param[out] key_buffer         Buffer where the key data is to be written.
 * \param[in]  key_buffer_size    Size of \p key_buffer in bytes.
 * \param[out] key_buffer_length  On success, the number of bytes written in
 *                                \p key_buffer.
 *
 * \retval #PSA_SUCCESS
 *         The key was successfully generated.
 * \retval #PSA_ERROR_NOT_SUPPORTED
 *         Key length or type not supported.
 * \retval #PSA_ERROR_BUFFER_TOO_SMALL
 *         The size of \p key_buffer is too small.
 */
psa_status_t mbedtls_psa_mlkem_generate_key(
    const psa_key_attributes_t *attributes,
    uint8_t *key_buffer, size_t key_buffer_size, size_t *key_buffer_length);

/**
 * \brief Encapsulate an MLKEM key.
 *
 * \param[in]  attributes         The attributes of the MLKEM encapsulation key.
 * \param[in]  key_buffer         Buffer holding the key data.
 * \param[in]  key_buffer_size    Size of \p key_buffer in bytes.
 * \param[out] ciphertext         Buffer where the ciphertext is to be written.
 * \param[out] ciphertext_len     Size of \p ciphertext in bytes.
 * \param[out] shared_secret      Buffer where the shared secret is to be written.
 * \param[out] shared_secret_len  On success, the number of bytes written in
 *                                \p shared_secret.
 *
 * \retval #PSA_SUCCESS
 *         The key was successfully generated.
 * \retval #PSA_ERROR_NOT_SUPPORTED
 *         Key length or type not supported.
 * \retval #PSA_ERROR_BUFFER_TOO_SMALL
 *         The size of \p ciphertext is too small.
 */
psa_status_t mbedtls_psa_mlkem_encapsulate(
    const psa_key_attributes_t *attributes,
    uint8_t *key_buffer,
    size_t key_buffer_size,
    uint8_t *ciphertext,
    size_t ciphertext_len,
    uint8_t *shared_secret,
    size_t *shared_secret_len);

/**
 * \brief Decapsulate MLKEM ciphertext.
 *
 * \param[in]  attributes         The attributes of the MLKEM decapsulation key.
 * \param[in]  key_buffer         Buffer holding the key data.
 * \param[in]  key_buffer_size    Size of \p key_buffer in bytes.
 * \param[in]  ciphertext         Buffer holding the ciphertext data.
 * \param[in]  ciphertext_len     Size of \p ciphertext in bytes.
 * \param[out] shared_secret      Buffer where the shared secret is to be written.
 * \param[out] shared_secret_len  On success, the number of bytes written in
 *                                \p shared_secret.
 *
 * \retval #PSA_SUCCESS
 *         The key was successfully generated.
 * \retval #PSA_ERROR_NOT_SUPPORTED
 *         Key length or type not supported.
 */
psa_status_t mbedtls_psa_mlkem_decapsulate(
    const psa_key_attributes_t *attributes,
    uint8_t *key_buffer,
    size_t key_buffer_size,
    uint8_t *ciphertext,
    size_t ciphertext_len,
    uint8_t *shared_secret,
    size_t *shared_secret_len);

#endif /* PSA_CRYPTO_MLKEM_H */