/**
 * \file shake.h
 *
 * \brief This file provides an API for SHAKE-128 and SHAKE-256.
 *
 */

/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef MBEDTLS_SHAKE_H
 #define MBEDTLS_SHAKE_H
 #include "mbedtls/private_access.h"

 #include "mbedtls/build_info.h"
 #include "mbedtls/platform_util.h"

 #include "mbedtls/bignum.h"
 #include "mbedtls/md.h"

 #ifdef __cplusplus
extern "C" {
 #endif

 #if defined(MBEDTLS_SHAKE_ALT)
  #include "shake_alt.h"
 #else

// Not yet supported by mbedtls
 #endif

 #ifdef __cplusplus
}
 #endif

#endif                                 /* shake.h */
