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
#include <mbedtls/mlkem.h>
#include <mbedtls/error.h>

#if defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_ML_DSA_KEY_PAIR_GENERATE) || \
    defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_ML_DSA_SIGN) || \
    defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_ML_DSA_VERIFY)

uint32_t mbedtls_mlkem_get_random(const uint32_t rand_len, uint32_t * const p_random);

uint32_t mbedtls_mldsa_get_random(const uint32_t rand_len, uint32_t * const p_random)
{
    psa_status_t status = mbedtls_psa_get_random(MBEDTLS_PSA_RANDOM_STATE, (unsigned char *)p_random, rand_len);
    return (status == PSA_SUCCESS) ? 0x55555555U : 0xAAAAAAAAU;
}
#endif /* MBEDTLS_PSA_BUILTIN_KEY_TYPE_ML_DSA_KEY_PAIR_GENERATE ||
          * MBEDTLS_PSA_BUILTIN_KEY_TYPE_ML_DSA_SIGN ||
          * MBEDTLS_PSA_BUILTIN_KEY_TYPE_ML_DSA_VERIFY */

#if defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_ML_DSA_KEY_PAIR_GENERATE)
psa_status_t mbedtls_psa_mldsa_generate_key(
    const psa_key_attributes_t *attributes,
    uint8_t *key_buffer,  size_t key_buffer_size, size_t *key_buffer_length)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mldsa_context mldsa;
   
    mbedtls_mldsa_init(&mldsa);
    mldsa.public_key.key_data = (uint32_t *)key_buffer;
    mldsa.public_key.key_len = PSA_KEY_EXPORT_ML_DSA_PUB_KEY_SIZE(attributes->bits);
    mldsa.private_key.key_data = (uint32_t *)(key_buffer + mldsa.public_key.key_len);
    mldsa.private_key.key_len = PSA_KEY_EXPORT_ML_DSA_PRIV_KEY_SIZE(attributes->bits);
     
    if (key_buffer_size < mldsa.public_key.key_len + mldsa.private_key.key_len) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    ret = mbedtls_mldsa_generate_key(&mldsa, attributes->bits, mbedtls_mldsa_get_random);
    if (ret != 0) {
        return mbedtls_to_psa_error(ret);
    }

    *key_buffer_length = mldsa.public_key.key_len + mldsa.private_key.key_len;

    return mbedtls_to_psa_error(ret);
}
#endif /* MBEDTLS_PSA_BUILTIN_KEY_TYPE_ML_DSA_KEY_PAIR_GENERATE */

#if defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_ML_DSA_VERIFY)
psa_status_t mbedtls_psa_mldsa_verify(
    const psa_key_bits_t bits,
    uint8_t *key_buffer,
    size_t key_buffer_size,
    uint8_t *signature,
    size_t signature_len,
    uint8_t *message,
    size_t message_len)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mldsa_context mldsa;
    mbedtls_mldsa_data_t msg;
    mbedtls_mldsa_data_t sign;
   
    mbedtls_mldsa_init(&mldsa);
    mldsa.public_key.key_data = (uint32_t *)key_buffer;
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
    uint8_t *key_buffer,
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
    mldsa.private_key.key_data = (uint32_t *)(key_buffer + PSA_KEY_EXPORT_ML_DSA_PUB_KEY_SIZE(bits));
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