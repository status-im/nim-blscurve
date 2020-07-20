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
 * @file core.h
 * @author Mike Scott
 * @brief Main Header File
 *
 */

#ifndef CORE_H
#define CORE_H

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <inttypes.h>
#include "arch.h"

/* modulus types */

#define NOT_SPECIAL 0        /**< Modulus of no exploitable form */
#define PSEUDO_MERSENNE 1      /**< Pseudo-mersenne modulus of form $2^n-c$  */
#define MONTGOMERY_FRIENDLY 3  /**< Montgomery Friendly modulus of form $2^a(2^b-c)-1$  */
#define GENERALISED_MERSENNE 2 /**< Generalised-mersenne modulus of form $2^n-2^m-1$, GOLDILOCKS only */

/* Curve types */

#define WEIERSTRASS 0 /**< Short Weierstrass form curve  */
#define EDWARDS 1     /**< Edwards or Twisted Edwards curve  */
#define MONTGOMERY 2  /**< Montgomery form curve  */

/* Pairing-Friendly types */

#define NOT_PF 0
#define BN_CURVE 1
#define BLS12_CURVE 2
#define BLS24_CURVE 3
#define BLS48_CURVE 4

#define D_TYPE 0
#define M_TYPE 1

#define FP_ZILCH 0
#define FP_UNITY 1
#define FP_SPARSEST 2
#define FP_SPARSER 3
#define FP_SPARSE 4
#define FP_DENSE 5

#define NEGATOWER 0     // Extension field tower type
#define POSITOWER 1

/**
  @brief Portable representation of a big positive number
*/

typedef struct
{
    int len;   /**< length in bytes  */
    int max;   /**< max length allowed - enforce truncation  */
    char *val; /**< byte array  */
} octet;

#endif
