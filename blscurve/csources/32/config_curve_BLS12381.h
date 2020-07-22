/*
 * Copyright (c) 2012-2020 MIRACL UK Ltd.
 *
 * This file is part of MIRACL Core
 * (see https://github.com/miracl/core).
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * @file config_curve.h
 * @author Mike Scott
 * @brief Config Curve  Header File
 *
 */

#ifndef CONFIG_CURVE_BLS12381_H
#define CONFIG_CURVE_BLS12381_H

#include"core.h"
#include"config_field_BLS12381.h"

// ECP stuff

#define CURVETYPE_BLS12381 WEIERSTRASS
#define CURVE_A_BLS12381 0
#define PAIRING_FRIENDLY_BLS12381 BLS12_CURVE
#define CURVE_SECURITY_BLS12381 128

#if PAIRING_FRIENDLY_BLS12381 != NOT_PF
//#define USE_GLV_BLS12381     /**< Note this method is patented (GLV), so maybe you want to comment this out */
//#define USE_GS_G2_BLS12381 /**< Well we didn't patent it :) But may be covered by GLV patent :( */
#define USE_GS_GT_BLS12381 /**< Not patented, so probably OK to always use this */

#define POSITIVEX 0
#define NEGATIVEX 1

#define SEXTIC_TWIST_BLS12381 M_TYPE
#define SIGN_OF_X_BLS12381 NEGATIVEX

#define ATE_BITS_BLS12381 65
#define G2_TABLE_BLS12381 69

#endif

#if CURVE_SECURITY_BLS12381 == 128
#define AESKEY_BLS12381 16 /**< Symmetric Key size - 128 bits */
#define HASH_TYPE_BLS12381 SHA256  /**< Hash type */
#endif

#if CURVE_SECURITY_BLS12381 == 192
#define AESKEY_BLS12381 24 /**< Symmetric Key size - 192 bits */
#define HASH_TYPE_BLS12381 SHA384  /**< Hash type */
#endif

#if CURVE_SECURITY_BLS12381 == 256
#define AESKEY_BLS12381 32 /**< Symmetric Key size - 256 bits */
#define HASH_TYPE_BLS12381 SHA512  /**< Hash type */
#endif



#endif
