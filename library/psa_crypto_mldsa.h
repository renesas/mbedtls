/*
 *  PSA MLDSA layer on top of Mbed TLS crypto
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef PSA_CRYPTO_MLDSA_H
#define PSA_CRYPTO_MLDSA_H

#include <psa/crypto.h>
#include <mbedtls/mldsa.h>

/**
 * \brief Generate an MLDSA key.
 *
 * \note The signature of the function is that of a PSA driver generate_key
 *       entry point.
 *
 * \param[in]  attributes         The attributes for the MLDSA key to generate.
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
psa_status_t mbedtls_psa_mldsa_generate_key(
    const psa_key_attributes_t *attributes,
    uint8_t *key_buffer, size_t key_buffer_size, size_t *key_buffer_length);

/**
 * \brief Verify the signature over the input message.
 *
 * \param[in]  bits                 The algorithm strength in bits.
 * \param[in]  key_buffer           Buffer holding the key data.
 * \param[in]  key_buffer_size      Size of \p key_buffer in bytes.
 * \param[in]  signature            Buffer holding the signature data.
 * \param[in]  signature_len        Size of \p signature in bytes.
 * \param[in]  message              Buffer where the message is to be written.
 * \param[in]  message_len          Size of \p message in bytes.
 *
 * \retval #PSA_SUCCESS
 *         The signature was successfully verified.
 * \retval #PSA_ERROR_NOT_SUPPORTED
 *         Key length or type not supported.
 * \retval #PSA_ERROR_BUFFER_TOO_SMALL
 *         The size of \p ciphertext is too small.
 */
psa_status_t mbedtls_psa_mldsa_verify(
    const psa_key_bits_t bits,
    uint8_t *key_buffer,
    size_t key_buffer_size,
    uint8_t *signature,
    size_t signature_len,
    uint8_t *message,
    size_t message_len);

/**
 * \brief Generate a signature for the input message.
 *
 * \param[in]  bits                 The algorithm strength in bits.
 * \param[in]  key_buffer           Buffer holding the key data.
 * \param[in]  key_buffer_size      Size of \p key_buffer in bytes.
 * \param[in]  message              Buffer holding the message  data.
 * \param[in]  message_len          Size of \p message in bytes.
 * \param[out] signature            Buffer where the signature is to be written.
 * \param[out] signature_len        On success, the number of bytes written in
 *                                  \p signature.
 *
 * \retval #PSA_SUCCESS
 *         The signature  was successfully generated.
 * \retval #PSA_ERROR_NOT_SUPPORTED
 *         Key length or type not supported.
 */
psa_status_t mbedtls_psa_mldsa_sign(
    const psa_key_bits_t bits,
    uint8_t *key_buffer,
    size_t key_buffer_size,
    const uint8_t *message,
    size_t message_len,
    uint8_t *signature,
    size_t *signature_len);

#endif /* PSA_CRYPTO_MLDSA_H */