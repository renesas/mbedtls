/*
 *  PSA ML DSA layer on top of Mbed TLS crypto
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "common.h"

#if defined(MBEDTLS_PSA_CRYPTO_C)

#include <psa/crypto.h>
#include "psa_crypto_core.h"
#include "psa_crypto_mldsa.h"
#include "psa_crypto_random_impl.h"
#include "mbedtls/psa_util.h"

#include <stdlib.h>
#include <string.h>
#include "mbedtls/platform.h"
#include <mbedtls/mldsa.h>
#include <mbedtls/error.h>

#if defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_ML_DSA_KEY_PAIR_GENERATE) || \
    defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_ML_DSA_SIGN) || \
    defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_ML_DSA_VERIFY)

uint32_t mbedtls_mldsa_get_random(const uint32_t rand_len, uint32_t * const p_random);

uint32_t mbedtls_mldsa_get_random(const uint32_t rand_len, uint32_t * const p_random)
{
    psa_status_t status = mbedtls_psa_get_random(MBEDTLS_PSA_RANDOM_STATE, (unsigned char *)p_random, rand_len);
    return (status == PSA_SUCCESS) ? 0x55555555U : 0xAAAAAAAAU;
}
#endif /* MBEDTLS_PSA_BUILTIN_KEY_TYPE_ML_DSA_KEY_PAIR_GENERATE ||
          * MBEDTLS_PSA_BUILTIN_KEY_TYPE_ML_DSA_SIGN ||
          * MBEDTLS_PSA_BUILTIN_KEY_TYPE_ML_DSA_VERIFY */
         
#if defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_ML_DSA_KEY_PAIR_BASIC)
psa_status_t mbedtls_psa_mldsa_load_representation(
    psa_key_type_t type, psa_key_bits_t bits,
    const uint8_t *data, size_t data_length,
    mbedtls_mldsa_context **p_mldsa)
{

    *p_mldsa = mbedtls_calloc(1, sizeof(mbedtls_mldsa_context));
    if (*p_mldsa == NULL) {
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    }
    mbedtls_mldsa_init(*p_mldsa);
    
    if (PSA_KEY_TYPE_IS_PUBLIC_KEY(type)) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    else {
        (*p_mldsa)->private_key.key_data = (uint32_t *)data;
        (*p_mldsa)->private_key.key_len = PSA_KEY_EXPORT_ML_DSA_PRIV_KEY_SIZE(bits);
        (*p_mldsa)->public_key.key_data = (uint32_t *)(data + (*p_mldsa)->private_key.key_len);
        (*p_mldsa)->public_key.key_len = PSA_KEY_EXPORT_ML_DSA_PUB_KEY_SIZE(bits);
        (*p_mldsa)->seed.key_data = (uint32_t *)(data + (*p_mldsa)->private_key.key_len + (*p_mldsa)->public_key.key_len);
        (*p_mldsa)->seed.key_len = PSA_ML_DSA_SEED_SIZE;
    }

    return PSA_SUCCESS;
}
#endif
         
#if defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_ML_DSA_KEY_PAIR_IMPORT) || \
    defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_ML_DSA_KEY_PAIR_EXPORT) || \
    defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_ML_DSA_PUBLIC_KEY)

psa_status_t mbedtls_psa_mldsa_import_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *data, size_t data_length,
    uint8_t *key_buffer, size_t key_buffer_size,
    size_t *key_buffer_length, size_t *bits)
{
    psa_status_t status;

    if (PSA_KEY_TYPE_IS_PUBLIC_KEY(attributes->type)) {
        /* Until ASN.1 encoding is implemented, the public key is just raw bytes */
        memcpy(key_buffer, data, data_length);
        *key_buffer_length = data_length;
        (void)key_buffer_size;
        status = PSA_SUCCESS;
    } else {
        int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
        mbedtls_mldsa_context *mldsa = NULL;
        mbedtls_mldsa_data_t random_seed;
        
        /* Parse input */
        status = mbedtls_psa_mldsa_load_representation(attributes->type,
                                                       attributes->bits,
                                                       key_buffer,
                                                       key_buffer_size,
                                                       &mldsa);
        if (status != PSA_SUCCESS) {
            goto exit;
        }
        *bits = attributes->bits;

        random_seed.key_data = (uint32_t*)data;
        random_seed.key_len = PSA_ML_DSA_SEED_SIZE;

        ret = mbedtls_mldsa_expand_key_pair(mldsa, *bits, &random_seed, mbedtls_mldsa_get_random);
        if (ret != 0) {
            status = mbedtls_to_psa_error(ret);
            goto exit;
        }
        *key_buffer_length = mldsa->private_key.key_len; + mldsa->public_key.key_len + PSA_ML_DSA_SEED_SIZE;
exit:
        if (status != PSA_SUCCESS) {
            mbedtls_free(mldsa);
        }
    }
    return status;
}

psa_status_t mbedtls_psa_mldsa_export_key(psa_key_type_t type,
                                          psa_key_bits_t bits,
                                          mbedtls_mldsa_context *mldsa,
                                          uint8_t *data,
                                          size_t data_size,
                                          size_t *data_length)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    if (PSA_KEY_TYPE_IS_KEY_PAIR(type)) {
        if (data_size < mldsa->seed.key_len) {
            return PSA_ERROR_BUFFER_TOO_SMALL;
        }
        ret = mbedtls_mldsa_export_keypair(mldsa, data, data_length);
    }
    else {
        if (data_size < PSA_KEY_EXPORT_ML_DSA_PUB_KEY_SIZE(bits)) {
            return PSA_ERROR_BUFFER_TOO_SMALL;
        }
        ret = mbedtls_mldsa_export_public_key(mldsa, data, data_length);
    }

    if (ret != 0) {
        return mbedtls_to_psa_error(ret);
    }
    return PSA_SUCCESS;
}

psa_status_t mbedtls_psa_mldsa_export_public_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    uint8_t *data, size_t data_size, size_t *data_length)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    mbedtls_mldsa_context *mldsa = NULL;

    status = mbedtls_psa_mldsa_load_representation(
        attributes->type, attributes->bits,
        key_buffer, key_buffer_size, &mldsa);
    if (status != PSA_SUCCESS) {
        goto exit;
    }

    status = mbedtls_psa_mldsa_export_key(PSA_KEY_TYPE_ML_DSA_PUBLIC_KEY, attributes->bits, mldsa, data, data_size, data_length);

exit:
    if (status != PSA_SUCCESS) {
        mbedtls_free(mldsa);
    }
    return status;
}
#endif /* defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_ML_DSA_KEY_PAIR_IMPORT) ||
        * defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_ML_DSA_KEY_PAIR_EXPORT) ||
        * defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_ML_DSA_PUBLIC_KEY) */

#if defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_ML_DSA_KEY_PAIR_GENERATE)
psa_status_t mbedtls_psa_mldsa_generate_key(
    const psa_key_attributes_t *attributes,
    uint8_t *key_buffer,  size_t key_buffer_size, size_t *key_buffer_length)
{
    psa_status_t status = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mldsa_context *mldsa = NULL;

    /* Parse input */
    status = mbedtls_psa_mldsa_load_representation(attributes->type,
                                                   attributes->bits,
                                                   key_buffer,
                                                   key_buffer_size,
                                                   &mldsa);
    if (status != PSA_SUCCESS) {
        goto exit;
    }
     
    if (key_buffer_size < mldsa->public_key.key_len + mldsa->private_key.key_len + mldsa->seed.key_len) {
        status = PSA_ERROR_BUFFER_TOO_SMALL;
        goto exit;
    }

    int ret = mbedtls_mldsa_generate_key(mldsa, attributes->bits, mbedtls_mldsa_get_random);
    if (ret != 0) {
        status = mbedtls_to_psa_error(ret);
        goto exit;
    }

    *key_buffer_length = mldsa->public_key.key_len + mldsa->private_key.key_len + mldsa->seed.key_len;

exit:
    if (status != PSA_SUCCESS) {
        mbedtls_free(mldsa);
    }
    return status;
}
#endif /* MBEDTLS_PSA_BUILTIN_KEY_TYPE_ML_DSA_KEY_PAIR_GENERATE */

#if defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_ML_DSA_VERIFY)
psa_status_t mbedtls_psa_mldsa_verify(
    const psa_key_bits_t bits,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    const uint8_t *signature,
    size_t signature_len,
    const uint8_t *message,
    size_t message_len)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mldsa_context mldsa;
    mbedtls_mldsa_data_t msg;
    mbedtls_mldsa_data_t sign;
   
    // Probably need to do some special handling depending on if the key is just a public one like MLKEM
    mbedtls_mldsa_init(&mldsa);
    mldsa.public_key.key_data = (uint32_t *)(key_buffer + PSA_KEY_EXPORT_ML_DSA_PRIV_KEY_SIZE(bits));
    mldsa.public_key.key_len = PSA_KEY_EXPORT_ML_DSA_PUB_KEY_SIZE(bits);
    msg.key_data = (uint32_t *)message;
    msg.key_len = message_len;
    sign.key_data = (uint32_t *)signature;
    sign.key_len = signature_len;

    ret = mbedtls_mldsa_verify(&mldsa, bits, &sign, &msg, mbedtls_mldsa_get_random);
    if (ret != 0) {
        return mbedtls_to_psa_error(ret);
    }
    if (sign.key_len > signature_len) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }
    if (msg.key_len > message_len) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    return mbedtls_to_psa_error(ret);
}
#endif /* MBEDTLS_PSA_BUILTIN_KEY_TYPE_ML_DSA_VERIFY */

#if defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_ML_DSA_SIGN)
psa_status_t mbedtls_psa_mldsa_sign(
    const psa_key_bits_t bits,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    const uint8_t *message,
    size_t message_len,
    uint8_t *signature,
    size_t signature_size,
    size_t *signature_len)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mldsa_context mldsa;
    mbedtls_mldsa_data_t msg;
    mbedtls_mldsa_data_t sign;
   
    mbedtls_mldsa_init(&mldsa);
    mldsa.private_key.key_data = (uint32_t *)key_buffer;
    mldsa.private_key.key_len = PSA_KEY_EXPORT_ML_DSA_PRIV_KEY_SIZE(bits);
    msg.key_data = (uint32_t *)message;
    msg.key_len = message_len;
    sign.key_data = (uint32_t *)signature;
    sign.key_len = signature_size;

    ret = mbedtls_mldsa_sign(&mldsa, bits, &msg, &sign, mbedtls_mldsa_get_random);
    if (ret != 0) {
        return mbedtls_to_psa_error(ret);
    }
    if (sign.key_len > signature_size) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }
    *signature_len = sign.key_len;
    return mbedtls_to_psa_error(ret);
}
#endif /* MBEDTLS_PSA_BUILTIN_KEY_TYPE_ML_DSA_SIGN */

#endif /* MBEDTLS_PSA_CRYPTO_C */