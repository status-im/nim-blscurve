/*
	Licensed to the Apache Software Foundation (ASF) under one
	or more contributor license agreements.  See the NOTICE file
	distributed with this work for additional information
	regarding copyright ownership.  The ASF licenses this file
	to you under the Apache License, Version 2.0 (the
	"License"); you may not use this file except in compliance
	with the License.  You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing,
	software distributed under the License is distributed on an
	"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
	KIND, either express or implied.  See the License for the
	specific language governing permissions and limitations
	under the License.
*/

/**
 * @file pair_BLS381.h
 * @author Mike Scott
 * @brief PAIR Header File
 *
 */

#ifndef PAIR_BLS381_H
#define PAIR_BLS381_H

#include "fp12_BLS381.h"
#include "ecp2_BLS381.h"
#include "ecp_BLS381.h"

/* Pairing constants */

extern const BIG_384_29 CURVE_Bnx_BLS381; /**< BN curve x parameter */
extern const BIG_384_29 CURVE_Cru_BLS381; /**< BN curve Cube Root of Unity */

extern const BIG_384_29 CURVE_W_BLS381[2];	 /**< BN curve constant for GLV decomposition */
extern const BIG_384_29 CURVE_SB_BLS381[2][2]; /**< BN curve constant for GLV decomposition */
extern const BIG_384_29 CURVE_WB_BLS381[4];	 /**< BN curve constant for GS decomposition */
extern const BIG_384_29 CURVE_BB_BLS381[4][4]; /**< BN curve constant for GS decomposition */

/* Pairing function prototypes */

/**	@brief Precompute line functions for n-pairing
 *
	@param r array of precomputed FP12 products of line functions
	@param PV ECP2 instance, an element of G2
	@param QV ECP instance, an element of G1

 */
extern void PAIR_BLS381_another(FP12_BLS381 r[],ECP2_BLS381* PV,ECP_BLS381* QV);

/**	@brief Calculate Miller loop for Optimal ATE pairing e(P,Q)
 *
	@param r FP12 result of the pairing calculation e(P,Q)
	@param P ECP2 instance, an element of G2
	@param Q ECP instance, an element of G1

 */
extern void PAIR_BLS381_ate(FP12_BLS381 *r,ECP2_BLS381 *P,ECP_BLS381 *Q);
/**	@brief Calculate Miller loop for Optimal ATE double-pairing e(P,Q).e(R,S)
 *
	Faster than calculating two separate pairings
	@param r FP12 result of the pairing calculation e(P,Q).e(R,S), an element of GT
	@param P ECP2 instance, an element of G2
	@param Q ECP instance, an element of G1
	@param R ECP2 instance, an element of G2
	@param S ECP instance, an element of G1
 */
extern void PAIR_BLS381_double_ate(FP12_BLS381 *r,ECP2_BLS381 *P,ECP_BLS381 *Q,ECP2_BLS381 *R,ECP_BLS381 *S);
/**	@brief Final exponentiation of pairing, converts output of Miller loop to element in GT
 *
	Here p is the internal modulus, and r is the group order
	@param x FP12, on exit = x^((p^12-1)/r)
 */
extern void PAIR_BLS381_fexp(FP12_BLS381 *x);
/**	@brief Fast point multiplication of a member of the group G1 by a BIG number
 *
	May exploit endomorphism for speed.
	@param Q ECP member of G1.
	@param b BIG multiplier

 */
extern void PAIR_BLS381_G1mul(ECP_BLS381 *Q,BIG_384_29 b);
/**	@brief Fast point multiplication of a member of the group G2 by a BIG number
 *
	May exploit endomorphism for speed.
	@param P ECP2 member of G1.
	@param b BIG multiplier

 */
extern void PAIR_BLS381_G2mul(ECP2_BLS381 *P,BIG_384_29 b);
/**	@brief Fast raising of a member of GT to a BIG power
 *
	May exploit endomorphism for speed.
	@param x FP12 member of GT.
	@param b BIG exponent

 */
extern void PAIR_BLS381_GTpow(FP12_BLS381 *x,BIG_384_29 b);
/**	@brief Tests FP12 for membership of GT
 *
	@param x FP12 instance
	@return 1 if x is in GT, else return 0

 */
extern int PAIR_BLS381_GTmember(FP12_BLS381 *x);

/**	@brief Prepare Ate parameter
 *
	@param n BIG parameter
	@param n3 BIG paramter = 3*n
	@return number of nits in n3

 */
extern int PAIR_BLS381_nbits(BIG_384_29 n3,BIG_384_29 n);

/**	@brief Initialise structure for multi-pairing
 *
	@param r FP12 array, to be initialised to 1

 */
extern void PAIR_BLS381_initmp(FP12_BLS381 r[]);


/**	@brief Miller loop
 *
 	@param res FP12 result
	@param r FP12 precomputed array of accumulated line functions

 */
extern void PAIR_BLS381_miller(FP12_BLS381 *res,FP12_BLS381 r[]);

#endif
