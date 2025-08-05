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

#if defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_ML_DSA_KEY_PAIR_GENERATE) || \
    defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_ML_DSA_SIGN) || \
    defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_ML_DSA_VERIFY)

uint32_t mbedtls_mlkem_get_random(const uint32_t rand_len, uint32_t * const p_random);
#define MBEDTLS_MLKEM_TEST_FIXED_TRNG
#if defined(MBEDTLS_MLKEM_TEST_FIXED_TRNG)
// Used by mbedtls_mldsa_generate_key()
const uint8_t  z[32] = {   /* z */
    0x1A, 0x39, 0x41, 0x11, 0x16, 0x38, 0x03, 0xFE, 0x2E, 0x85, 0x19, 0xC3, 0x35, 0xA6, 0x86, 0x75,
    0x56, 0x33, 0x8E, 0xAD, 0xAF, 0xA2, 0x2B, 0x5F, 0xC5, 0x57, 0x43, 0x05, 0x60, 0xCC, 0xD6, 0x93,
};
const uint8_t  d[32] = {   /* d */
    0x1E, 0xB4, 0x40, 0x0A, 0x01, 0x62, 0x9D, 0x51, 0x79, 0x74, 0xE2, 0xCD, 0x85, 0xB9, 0xDE, 0xF5,
    0x90, 0x82, 0xDE, 0x50, 0x8E, 0x6F, 0x9C, 0x2B, 0x0E, 0x34, 0x1E, 0x12, 0x96, 0x59, 0x55, 0xCA,
};
// Used by mbedtls_mldsa_encapsulate() and mbedtls_mldsa_decapsulate()
const uint8_t  m[32] = { /* m */
    0xAF, 0x9B, 0x6C, 0xAE, 0x18, 0x7C, 0x40, 0x72, 0x56, 0xFC, 0x9D, 0x3F, 0x3B, 0xE3, 0x70, 0x10,
    0xFF, 0xAF, 0x55, 0xD0, 0xE6, 0x87, 0xA1, 0x28, 0xF1, 0x7C, 0x7F, 0x62, 0xEB, 0x68, 0x84, 0xD3,
};
static int random_call_count = 0;

uint32_t mbedtls_mldsa_get_random(const uint32_t rand_len, uint32_t * const p_random)
{
    if (0 == random_call_count)
    {
        /* d */
        memcpy(p_random, d, rand_len);
    }
    else if (1 == random_call_count)
    {
        /* z */
        memcpy(p_random, z, rand_len);
    }
    else if (2 == random_call_count)
    {
        /* fixed data */
        memcpy(p_random, z, rand_len);
    }
    else
    {
        memcpy(p_random, m, rand_len);
    }

    random_call_count++;

    return 0x55555555;
}
#else
uint32_t mbedtls_mldsa_get_random(const uint32_t rand_len, uint32_t * const p_random)
{
    psa_status_t status = mbedtls_psa_get_random(MBEDTLS_PSA_RANDOM_STATE, (unsigned char *)p_random, rand_len);
    return (status == PSA_SUCCESS) ? 0x55555555U : 0xAAAAAAAAU;
}
#endif
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
#if defined(MBEDTLS_MLKEM_TEST_FIXED_TRNG)
    random_call_count = 0;
#endif
   
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
psa_status_t mbedtls_psa_mlkem_encapsulate(
    const psa_key_bits_t bits,
    uint8_t *key_buffer,
    size_t key_buffer_size,
    uint8_t *output_key_buffer,
    size_t output_key_buffer_size,
    uint8_t *ciphertext,
    size_t ciphertext_size,
    size_t *ciphertext_length)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mlkem_context mlkem;
    mbedtls_mlkem_data_t cipher;
    mbedtls_mlkem_data_t shared_key;
#if defined(MBEDTLS_MLKEM_TEST_FIXED_TRNG)
    random_call_count = 3;
#endif
   
    mbedtls_mlkem_init(&mlkem);
    mlkem.public_key.key_data = (uint32_t *)key_buffer;
    mlkem.public_key.key_len = PSA_KEY_EXPORT_ML_DSA_PUB_KEY_SIZE(bits);
    cipher.key_data = (uint32_t *)ciphertext;
    cipher.key_len = ciphertext_size;
    shared_key.key_data = (uint32_t *)output_key_buffer;
    shared_key.key_len = output_key_buffer_size;

    ret = mbedtls_mlkem_encapsulate(&mlkem, bits, &cipher, &shared_key, mbedtls_mlkem_get_random);
    if (ret != 0) {
        return mbedtls_to_psa_error(ret);
    }
    if (shared_key.key_len > output_key_buffer_size) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }
    if (cipher.key_len > ciphertext_size) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }
    *ciphertext_length = cipher.key_len;

    return mbedtls_to_psa_error(ret);
}
#endif /* MBEDTLS_PSA_BUILTIN_KEY_TYPE_ML_DSA_VERIFY */

#if defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_ML_DSA_SIGN)
psa_status_t mbedtls_psa_mlkem_decapsulate(
    const psa_key_bits_t bits,
    uint8_t *key_buffer,
    size_t key_buffer_size,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    uint8_t *shared_secret,
    size_t *shared_secret_len)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mlkem_context mlkem;
    mbedtls_mlkem_data_t cipher;
    mbedtls_mlkem_data_t shared_key;
#if defined(MBEDTLS_MLKEM_TEST_FIXED_TRNG)
    random_call_count = 3;
#endif
   
    mbedtls_mlkem_init(&mlkem);
    mlkem.private_key.key_data = (uint32_t *)(key_buffer + PSA_KEY_EXPORT_ML_DSA_PUB_KEY_SIZE(bits));
    mlkem.private_key.key_len = PSA_KEY_EXPORT_ML_DSA_PRIV_KEY_SIZE(bits);
    cipher.key_data = (uint32_t *)ciphertext;
    cipher.key_len = ciphertext_len;
    shared_key.key_data = (uint32_t *)shared_secret;
    shared_key.key_len = *shared_secret_len;

    ret = mbedtls_mlkem_decapsulate(&mlkem, bits, &cipher, &shared_key, mbedtls_mlkem_get_random);
    if (ret != 0) {
        return mbedtls_to_psa_error(ret);
    }
    if (shared_key.key_len > *shared_secret_len) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }
    *shared_secret_len = shared_key.key_len;

    return mbedtls_to_psa_error(ret);
}
#endif /* MBEDTLS_PSA_BUILTIN_KEY_TYPE_ML_DSA_SIGN */

#endif /* MBEDTLS_PSA_CRYPTO_C */