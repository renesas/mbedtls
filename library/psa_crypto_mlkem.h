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


/** Load the contents of a key buffer into an internal MLKEM representation
 *
 * \param[in] type          The type of key contained in \p data.
 * \param[in] bits          The algorithm strength in bits.
 * \param[in] data          The buffer from which to load the representation.
 * \param[in] data_length   The size in bytes of \p data.
 * \param[out] p_mlkem      Returns a pointer to an MLKEM context on success.
 *                          The caller is responsible for freeing both the
 *                          contents of the context and the context itself
 *                          when done.
 */
psa_status_t mbedtls_psa_mlkem_load_representation(psa_key_type_t type,
                                                   psa_key_bits_t bits,
                                                   const uint8_t *data,
                                                   size_t data_length,
                                                   mbedtls_mlkem_context **p_mlkem);

/** Import an MLKEM key in binary format.
 *
 * \note The signature of this function is that of a PSA driver
 *       import_key entry point. This function behaves as an import_key
 *       entry point as defined in the PSA driver interface specification for
 *       transparent drivers.
 *
 * \param[in]  attributes       The attributes for the key to import.
 * \param[in]  data             The buffer containing the key data in import
 *                              format.
 * \param[in]  data_length      Size of the \p data buffer in bytes.
 * \param[out] key_buffer       The buffer containing the key data in output
 *                              format.
 * \param[in]  key_buffer_size  Size of the \p key_buffer buffer in bytes. This
 *                              size is greater or equal to \p data_length.
 * \param[out] key_buffer_length  The length of the data written in \p
 *                                key_buffer in bytes.
 * \param[out] bits             The key size in number of bits.
 *
 * \retval #PSA_SUCCESS  The MLKEM key was imported successfully.
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 *         The key data is not correctly formatted.
 * \retval #PSA_ERROR_NOT_SUPPORTED \emptydescription
 * \retval #PSA_ERROR_INSUFFICIENT_MEMORY \emptydescription
 * \retval #PSA_ERROR_CORRUPTION_DETECTED \emptydescription
 */
psa_status_t mbedtls_psa_mlkem_import_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *data, size_t data_length,
    uint8_t *key_buffer, size_t key_buffer_size,
    size_t *key_buffer_length, size_t *bits);

/** Export an MLKEM key to export representation
 *
 * \param[in] type          The type of key (public/private) to export
 * \param[in] mlkem         The internal MLKEM representation from which to export
 * \param[out] data         The buffer to export to
 * \param[in] data_size     The length of the buffer to export to
 * \param[out] data_length  The amount of bytes written to \p data
 */
psa_status_t mbedtls_psa_mlkem_export_key(psa_key_type_t type,
                                          psa_key_bits_t bits,
                                          mbedtls_mlkem_context *mlkem,
                                          uint8_t *data,
                                          size_t data_size,
                                          size_t *data_length);
                                         
/** Export an MLKEM public key or the public part of an MLKEM key pair in binary
 *  format.
 *
 * \note The signature of this function is that of a PSA driver
 *       export_public_key entry point. This function behaves as an
 *       export_public_key entry point as defined in the PSA driver interface
 *       specification.
 *
 * \param[in]  attributes       The attributes for the key to export.
 * \param[in]  key_buffer       Material or context of the key to export.
 * \param[in]  key_buffer_size  Size of the \p key_buffer buffer in bytes.
 * \param[out] data             Buffer where the key data is to be written.
 * \param[in]  data_size        Size of the \p data buffer in bytes.
 * \param[out] data_length      On success, the number of bytes written in
 *                              \p data
 *
 * \retval #PSA_SUCCESS  The MLKEM public key was exported successfully.
 * \retval #PSA_ERROR_NOT_SUPPORTED \emptydescription
 * \retval #PSA_ERROR_COMMUNICATION_FAILURE \emptydescription
 * \retval #PSA_ERROR_HARDWARE_FAILURE \emptydescription
 * \retval #PSA_ERROR_CORRUPTION_DETECTED \emptydescription
 * \retval #PSA_ERROR_STORAGE_FAILURE \emptydescription
 * \retval #PSA_ERROR_INSUFFICIENT_MEMORY \emptydescription
 */
psa_status_t mbedtls_psa_mlkem_export_public_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    uint8_t *data, size_t data_size, size_t *data_length);

/**
 * \brief Generate an MLKEM key.
 *
 * \note The signature of the function is that of a PSA driver generate_key
 *       entry point.
 *
 * \param[in]  bits               The algorithm strength in bits.
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
    const psa_key_bits_t bits,
    uint8_t *key_buffer, size_t key_buffer_size, size_t *key_buffer_length);

/**
 * \brief Encapsulate an MLKEM key.
 *
 * \param[in]  attributes               The attributes for the key to encapsulate.
 * \param[in]  key_buffer               Buffer holding the key data.
 * \param[in]  key_buffer_size          Size of \p key_buffer in bytes.
 * \param[out] output_key_buffer        Buffer holding the key data.
 * \param[out] output_key_buffer_size   Size of \p output_key_buffer in bytes.
 * \param[out] ciphertext               Buffer where the ciphertext is to be written.
 * \param[in]  ciphertext_size          Size of \p ciphertext in bytes.
 * \param[out] ciphertext_length        On success, the number of bytes written in
 *                                      \p ciphertext.
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
    uint8_t *output_key_buffer,
    size_t output_key_buffer_size,
    uint8_t *ciphertext,
    size_t ciphertext_size,
    size_t *ciphertext_length);

/**
 * \brief Decapsulate MLKEM ciphertext.
 *
 * \param[in]  bits               The algorithm strength in bits.
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
    const psa_key_bits_t bits,
    uint8_t *key_buffer,
    size_t key_buffer_size,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    uint8_t *shared_secret,
    size_t *shared_secret_len);

#endif /* PSA_CRYPTO_MLKEM_H */