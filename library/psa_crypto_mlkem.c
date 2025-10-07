/*
 *  PSA MLKEM layer on top of Mbed TLS crypto
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "common.h"

#if defined(MBEDTLS_PSA_CRYPTO_C)

#include <psa/crypto.h>
#include "psa_crypto_core.h"
#include "psa_crypto_mlkem.h"
#include "psa_crypto_random_impl.h"
#include "mbedtls/psa_util.h"

#include <stdlib.h>
#include <string.h>
#include "mbedtls/platform.h"
#include <mbedtls/mlkem.h>
#include <mbedtls/error.h>

#if defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_MLKEM_KEY_PAIR_GENERATE) || \
    defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_MLKEM_KEY_ENCAPSULATE) || \
    defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_MLKEM_KEY_DECAPSULATE)

uint32_t mbedtls_mlkem_get_random(const uint32_t rand_len, uint32_t * const p_random);

uint32_t mbedtls_mlkem_get_random(const uint32_t rand_len, uint32_t * const p_random)
{
    psa_status_t status = mbedtls_psa_get_random(MBEDTLS_PSA_RANDOM_STATE, (unsigned char *)p_random, rand_len);
    return (status == PSA_SUCCESS) ? 0x55555555U : 0xAAAAAAAAU;
}
#endif /* MBEDTLS_PSA_BUILTIN_KEY_TYPE_MLKEM_KEY_PAIR_GENERATE ||
          * MBEDTLS_PSA_BUILTIN_KEY_TYPE_MLKEM_KEY_ENCAPSULATE ||
          * MBEDTLS_PSA_BUILTIN_KEY_TYPE_MLKEM_KEY_DECAPSULATE */

#if defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_MLKEM_KEY_PAIR_BASIC)
psa_status_t mbedtls_psa_mlkem_load_representation(
    psa_key_type_t type, psa_key_bits_t bits,
    const uint8_t *data, size_t data_length,
    mbedtls_mlkem_context **p_mlkem)
{

    *p_mlkem = mbedtls_calloc(1, sizeof(mbedtls_mlkem_context));
    if (*p_mlkem == NULL) {
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    }
    mbedtls_mlkem_init(*p_mlkem);
    
    if (PSA_KEY_TYPE_IS_PUBLIC_KEY(type)) {
        (*p_mlkem)->encaps_key.key_data = (uint32_t *)data;
        (*p_mlkem)->encaps_key.key_len = data_length;
    }
    else {
        (*p_mlkem)->decaps_key.key_data = (uint32_t *)data;
        (*p_mlkem)->decaps_key.key_len = PSA_KEY_GEN_ML_KEM_PRIVATE_KEY_SIZE(bits);
        (*p_mlkem)->d.key_data = (uint32_t *)(data + (*p_mlkem)->decaps_key.key_len);
        (*p_mlkem)->d.key_len = PSA_ML_KEM_SEED_SIZE;
        (*p_mlkem)->z.key_data = (uint32_t *)(data + (*p_mlkem)->decaps_key.key_len + (*p_mlkem)->d.key_len);
        (*p_mlkem)->z.key_len = PSA_ML_KEM_SEED_SIZE;
    }

    return PSA_SUCCESS;
}
#endif
         
#if defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_MLKEM_KEY_PAIR_IMPORT) || \
    defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_MLKEM_KEY_PAIR_EXPORT) || \
    defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_MLKEM_PUBLIC_KEY)

psa_status_t mbedtls_psa_mlkem_import_key(const psa_key_attributes_t *attributes,
                                          const uint8_t *data,
                                          size_t data_length,
                                          uint8_t *key_buffer,
                                          size_t key_buffer_size,
                                          size_t *key_buffer_length,
                                          size_t *bits)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    if (PSA_KEY_TYPE_IS_PUBLIC_KEY(attributes->type)) {
        /* Until ASN.1 encoding is implemented, the public key is just raw bytes */
        memcpy(key_buffer, data, data_length);
        *key_buffer_length = data_length;
        (void)key_buffer_size;
        status = PSA_SUCCESS;
    } else {
        int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
        mbedtls_mlkem_context *mlkem = NULL;
        mbedtls_mlkem_data_t random_d;
        mbedtls_mlkem_data_t random_z;
        
        /* Parse input */
        status = mbedtls_psa_mlkem_load_representation(attributes->type,
                                                       attributes->bits,
                                                       key_buffer,
                                                       key_buffer_size,
                                                       &mlkem);
        if (status != PSA_SUCCESS) {
            goto exit;
        }
        *bits = attributes->bits;

        random_d.key_data = (uint32_t*)data;
        random_d.key_len = PSA_ML_KEM_SEED_SIZE;
        random_z.key_data = (uint32_t*)(data + random_d.key_len);
        random_z.key_len = PSA_ML_KEM_SEED_SIZE;

        ret = mbedtls_mlkem_expand_key_pair(mlkem, *bits, &random_d, &random_z, mbedtls_mlkem_get_random);
        if (ret != 0) {
            status = mbedtls_to_psa_error(ret);
            goto exit;
        }
        *key_buffer_length = PSA_ML_KEM_SEED_SIZE + PSA_ML_KEM_SEED_SIZE + mlkem->decaps_key.key_len;

exit:
        mbedtls_free(mlkem);
    }
    return status;
}

psa_status_t mbedtls_psa_mlkem_export_key(psa_key_type_t type,
                                          psa_key_bits_t bits,
                                          mbedtls_mlkem_context *mlkem,
                                          uint8_t *data,
                                          size_t data_size,
                                          size_t *data_length)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    if (PSA_KEY_TYPE_IS_KEY_PAIR(type)) {
        if (data_size < mlkem->d.key_len + mlkem->z.key_len) {
            return PSA_ERROR_BUFFER_TOO_SMALL;
        }
        ret = mbedtls_mlkem_export_keypair(mlkem, data, data_length);
    }
    else {
        if (data_size < PSA_KEY_GEN_ML_KEM_PUBLIC_KEY_MAX_SIZE(bits)) {
            return PSA_ERROR_BUFFER_TOO_SMALL;
        }
        ret = mbedtls_mlkem_export_public_key(mlkem, bits);
        if (ret == 0) {
            memcpy(data, mlkem->encaps_key.key_data, mlkem->encaps_key.key_len);
            *data_length = mlkem->encaps_key.key_len;
        }
    }

    if (ret != 0) {
        return mbedtls_to_psa_error(ret);
    }
    return PSA_SUCCESS;
}

psa_status_t mbedtls_psa_mlkem_export_public_key(const psa_key_attributes_t *attributes,
                                                 const uint8_t *key_buffer,
                                                 size_t key_buffer_size,
                                                 uint8_t *data,
                                                 size_t data_size,
                                                 size_t *data_length)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    mbedtls_mlkem_context *mlkem = NULL;

    status = mbedtls_psa_mlkem_load_representation(attributes->type,
                                                   attributes->bits,
                                                   key_buffer,
                                                   key_buffer_size,
                                                   &mlkem);
    if (status != PSA_SUCCESS) {
        goto exit;
    }

    status = mbedtls_psa_mlkem_export_key(PSA_KEY_TYPE_ML_KEM_PUBLIC_KEY, attributes->bits, mlkem, data, data_size, data_length);

exit:
    mbedtls_free(mlkem);
    return status;
}
#endif /* defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_MLKEM_KEY_PAIR_IMPORT) ||
        * defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_MLKEM_KEY_PAIR_EXPORT) ||
        * defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_MLKEM_PUBLIC_KEY) */

#if defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_MLKEM_KEY_PAIR_GENERATE)
psa_status_t mbedtls_psa_mlkem_generate_key(
    const psa_key_bits_t bits,
    uint8_t *key_buffer,  size_t key_buffer_size, size_t *key_buffer_length)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    mbedtls_mlkem_context *mlkem = NULL;
    
    /* Parse input */
    status = mbedtls_psa_mlkem_load_representation(PSA_KEY_TYPE_ML_KEM_KEY_PAIR,
                                                   bits,
                                                   key_buffer,
                                                   key_buffer_size,
                                                   &mlkem);
    if (status != PSA_SUCCESS) {
        goto exit;
    }

    if (key_buffer_size < (mlkem->decaps_key.key_len + mlkem->d.key_len + mlkem->z.key_len)) {
        status = PSA_ERROR_BUFFER_TOO_SMALL;
        goto exit;
    }

    int ret = mbedtls_mlkem_generate_key(mlkem, bits, mbedtls_mlkem_get_random);
    if (ret != 0) {
        status = mbedtls_to_psa_error(ret);
        goto exit;
    }

    *key_buffer_length = PSA_ML_KEM_SEED_SIZE + PSA_ML_KEM_SEED_SIZE + mlkem->decaps_key.key_len;

exit:
    mbedtls_free(mlkem);
    return status;
}
#endif /* MBEDTLS_PSA_BUILTIN_KEY_TYPE_MLKEM_KEY_PAIR_GENERATE */

#if defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_MLKEM_KEY_ENCAPSULATE)
psa_status_t mbedtls_psa_mlkem_encapsulate(const psa_key_attributes_t *attributes,
                                           uint8_t *key_buffer,
                                           size_t key_buffer_size,
                                           uint8_t *output_key_buffer,
                                           size_t output_key_buffer_size,
                                           uint8_t *ciphertext,
                                           size_t ciphertext_size,
                                           size_t *ciphertext_length)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mlkem_context *mlkem = NULL;
    mbedtls_mlkem_data_t cipher;
    mbedtls_mlkem_data_t shared_key;

    status = mbedtls_psa_mlkem_load_representation(attributes->type,
                                                   attributes->bits,
                                                   key_buffer,
                                                   key_buffer_size,
                                                   &mlkem);
    if (status != PSA_SUCCESS) {
        goto exit;
    }

    if (PSA_KEY_TYPE_IS_KEY_PAIR(attributes->type)) {
        ret = mbedtls_mlkem_export_public_key(mlkem, attributes->bits);
        if (ret != 0) {
            status = mbedtls_to_psa_error(ret);
            goto exit;
        }
    }

    cipher.key_data = (uint32_t *)ciphertext;
    cipher.key_len = ciphertext_size;
    shared_key.key_data = (uint32_t *)output_key_buffer;
    shared_key.key_len = output_key_buffer_size;

    if (key_buffer_size < mlkem->decaps_key.key_len) {
        status = PSA_ERROR_BUFFER_TOO_SMALL;
        goto exit;
    }

    ret = mbedtls_mlkem_encapsulate(mlkem, attributes->bits, &cipher, &shared_key, mbedtls_mlkem_get_random);
    if (ret != 0) {
        status = mbedtls_to_psa_error(ret);
        goto exit;
    }
    if (shared_key.key_len > output_key_buffer_size) {
        status = PSA_ERROR_BUFFER_TOO_SMALL;
        goto exit;
    }
    if (cipher.key_len > ciphertext_size) {
        status = PSA_ERROR_BUFFER_TOO_SMALL;
        goto exit;
    }
    *ciphertext_length = cipher.key_len;

exit:
    mbedtls_free(mlkem);
    return status;
}
#endif /* MBEDTLS_PSA_BUILTIN_KEY_TYPE_MLKEM_KEY_ENCAPSULATE */

#if defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_MLKEM_KEY_DECAPSULATE)
psa_status_t mbedtls_psa_mlkem_decapsulate(const psa_key_bits_t bits,
                                           uint8_t *key_buffer,
                                           size_t key_buffer_size,
                                           const uint8_t *ciphertext,
                                           size_t ciphertext_len,
                                           uint8_t *shared_secret,
                                           size_t *shared_secret_len)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    mbedtls_mlkem_context *mlkem = NULL;
    mbedtls_mlkem_data_t cipher;
    mbedtls_mlkem_data_t shared_key;
    
    status = mbedtls_psa_mlkem_load_representation(PSA_KEY_TYPE_ML_KEM_KEY_PAIR,
                                                   bits,
                                                   key_buffer,
                                                   key_buffer_size,
                                                   &mlkem);
    if (status != PSA_SUCCESS) {
        goto exit;
    }

    cipher.key_data = (uint32_t *)ciphertext;
    cipher.key_len = ciphertext_len;
    shared_key.key_data = (uint32_t *)shared_secret;
    shared_key.key_len = *shared_secret_len;
        
    if (key_buffer_size < mlkem->decaps_key.key_len) {
        status = PSA_ERROR_BUFFER_TOO_SMALL;
        goto exit;
    }

    int ret = mbedtls_mlkem_decapsulate(mlkem, bits, &cipher, &shared_key, mbedtls_mlkem_get_random);
    if (ret != 0) {
        status = mbedtls_to_psa_error(ret);
        goto exit;
    }
    if (shared_key.key_len > *shared_secret_len) {
        status = PSA_ERROR_BUFFER_TOO_SMALL;
        goto exit;
    }
    *shared_secret_len = shared_key.key_len;

exit:
    mbedtls_free(mlkem);
    return status;
}
#endif /* MBEDTLS_PSA_BUILTIN_KEY_TYPE_MLKEM_KEY_DECAPSULATE */

#endif /* MBEDTLS_PSA_CRYPTO_C */