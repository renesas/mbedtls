/**
 * \file psa/crypto_accel_driver.h
 * \brief PSA cryptography accelerator driver module
 *
 * This header declares types and function signatures for cryptography
 * drivers that access key material directly. This is meant for
 * on-chip cryptography accelerators.
 *
 * This file is part of the PSA Crypto Driver Model, containing functions for
 * driver developers to implement to enable hardware to be called in a
 * standardized way by a PSA Cryptographic API implementation. The functions
 * comprising the driver model, which driver authors implement, are not
 * intended to be called by application developers.
 */

/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
#ifndef PSA_CRYPTO_ACCEL_DRIVER_H
 #define PSA_CRYPTO_ACCEL_DRIVER_H

 #include "crypto_driver_common.h"
 #include <stdbool.h>

 #ifdef __cplusplus
extern "C" {
 #endif

/** Import vendor defined key data into a slot.
 *
 * `slot->type` must have been set previously.
 * This function assumes that the slot does not contain any key material yet.
 * On failure, the slot content is unchanged.
 *
 * Persistent storage is not affected.
 *
 * \param[in,out] slot  The key slot to import data into.
 *                      Its `type` field must have previously been set to
 *                      the desired key type.
 *                      It must not contain any key material yet.
 * \param[in] data      Buffer containing the key material to parse and import.
 * \param data_length   Size of \p data in bytes.
 * \param write_to_persistent_memory   Specify if the imported key needs to be written to persistent memory.
 *
 * \retval PSA_SUCCESS
 * \retval PSA_ERROR_INVALID_ARGUMENT
 * \retval PSA_ERROR_NOT_SUPPORTED
 * \retval PSA_ERROR_INSUFFICIENT_MEMORY
 * \retval Implementation dependent
 */
psa_status_t psa_import_key_into_slot_vendor(const psa_key_attributes_t * attributes,
                                             psa_key_slot_t             * slot,
                                             const uint8_t              * data,
                                             size_t                       data_length,
                                             mbedtls_svc_key_id_t       * key,
                                             bool                         write_to_persistent_memory);

/**
 * \brief Generate a vendor defined key or key pair.
 *
 * \note    This function has to be defined by the vendor if MBEDTLS_PSA_CRYPTO_ACCEL_DRV_C
 *          is defined. Do not use this function directly;
 *          to generate a key, use psa_generate_key() instead.
 *
 * \param[in] slot
 * \param[in] bits
 * \param[in] params
 * \param[in] params_data_length
 *
 *
 * \retval #PSA_SUCCESS
 *         Success.
 *         If the key is persistent, the key material and the key's metadata
 *         have been saved to persistent storage.
 *
 * \retval #PSA_ERROR_NOT_SUPPORTED
 * \retval Implementation dependent.
 */
psa_status_t psa_generate_key_vendor (psa_key_slot_t * slot,
                                      size_t           bits,
									  const psa_key_production_parameters_t *params,
									  size_t params_data_length);

/**
 * \brief Generate symmetric key of vendor defined format.
 *
 * \warning This function **can** fail! Callers MUST check the return status
 *          and MUST NOT use the content of the output buffer if the return
 *          status is not #PSA_SUCCESS.
 *
 * \note    This function has to be defined by the vendor if MBEDTLS_PSA_CRYPTO_ACCEL_DRV_C
 *          is defined.
 *          A weakly linked version is provided by default and returns
 *          PSA_ERROR_NOT_SUPPORTED. Do not use this function directly;
 *          to generate a key, use psa_generate_key() instead.
 *
 * \param[in] type          Type of symmetric key to be generated.
 * \param[out] output       Output buffer for the generated data.
 * \param[out] output_size  Number of bytes to generate and output.
 *
 * \retval #PSA_SUCCESS
 * \retval #PSA_ERROR_NOT_SUPPORTED
 * \retval Implementation dependent
 */
psa_status_t psa_generate_symmetric_vendor(psa_key_type_t type, size_t bits, uint8_t * output, size_t output_size);

/** Finalize the creation of a vendor defined key once its key material has been set.
 *
 * This entails writing the key to persistent storage.
 *
 * This function is to be called only by psa_finish_key_creation().
 *
 * \param[in,out] slot  Pointer to the slot with key material.
 *
 * \retval #PSA_SUCCESS
 *         The key was successfully created. The handle is now valid.
 * \return If this function fails, the key slot is an invalid state.
 */
psa_status_t psa_finish_key_creation_vendor(psa_key_slot_t * slot);								 

/**@}*/

 #ifdef __cplusplus
}
 #endif

#endif                                 /* PSA_CRYPTO_ACCEL_DRIVER_H */
