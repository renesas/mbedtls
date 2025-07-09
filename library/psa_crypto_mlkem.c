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

#if defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_MLKEM_KEY_PAIR_GENERATE)

uint32_t mbedtls_mlkem_get_random(const uint32_t rand_len, uint32_t * const p_random);

uint32_t mbedtls_mlkem_get_random(const uint32_t rand_len, uint32_t * const p_random)
{
    psa_status_t status = mbedtls_psa_get_random(MBEDTLS_PSA_RANDOM_STATE, p_random, rand_len);
    return (status == PSA_SUCCESS) ? 0x55555555U : 0xAAAAAAAAU;
}

psa_status_t mbedtls_psa_mlkem_generate_key(
    const psa_key_attributes_t *attributes,
    uint8_t *key_buffer,  size_t key_buffer_size, size_t *key_buffer_length)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mlkem_context mlkem;
   
    mbedtls_mlkem_init(&mlkem);
    mlkem.encaps_key.key_data = (uint32_t *)key_buffer;
    mlkem.encaps_key.key_len = PSA_KEY_EXPORT_MLKEM_ENC_KEY_SIZE(attributes->bits);
    mlkem.decaps_key.key_data = (uint32_t *)(key_buffer + mlkem.encaps_key.key_len);
    mlkem.decaps_key.key_len = PSA_KEY_EXPORT_MLKEM_DEC_KEY_SIZE(attributes->bits);
    ret = mbedtls_mlkem_generate_key(&mlkem, attributes->bits, mbedtls_mlkem_get_random);
    if (ret != 0) {
        return mbedtls_to_psa_error(ret);
    }
     
    if (key_buffer_size < mlkem.encaps_key.key_len + mlkem.decaps_key.key_len) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }
    *key_buffer_length = mlkem.encaps_key.key_len + mlkem.decaps_key.key_len;

    return mbedtls_to_psa_error(ret);
}
#endif /* MBEDTLS_PSA_BUILTIN_KEY_TYPE_MLKEM_KEY_PAIR_GENERATE */

#endif /* MBEDTLS_PSA_CRYPTO_C */