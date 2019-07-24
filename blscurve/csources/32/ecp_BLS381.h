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
 * @file ecp_BLS381.h
 * @author Mike Scott
 * @brief ECP Header File
 *
 */

#ifndef ECP_BLS381_H
#define ECP_BLS381_H

#include "fp_BLS381.h"
#include "config_curve_BLS381.h"

/* Curve Params - see rom_zzz.c */
extern const int CURVE_A_BLS381;         /**< Elliptic curve A parameter */
extern const int CURVE_Cof_I_BLS381;     /**< Elliptic curve cofactor */
extern const int CURVE_B_I_BLS381;       /**< Elliptic curve B_i parameter */
extern const BIG_384_29 CURVE_B_BLS381;     /**< Elliptic curve B parameter */
extern const BIG_384_29 CURVE_Order_BLS381; /**< Elliptic curve group order */
extern const BIG_384_29 CURVE_Cof_BLS381;   /**< Elliptic curve cofactor */

/* Generator point on G1 */
extern const BIG_384_29 CURVE_Gx_BLS381; /**< x-coordinate of generator point in group G1  */
extern const BIG_384_29 CURVE_Gy_BLS381; /**< y-coordinate of generator point in group G1  */


/* For Pairings only */

/* Generator point on G2 */
extern const BIG_384_29 CURVE_Pxa_BLS381; /**< real part of x-coordinate of generator point in group G2 */
extern const BIG_384_29 CURVE_Pxb_BLS381; /**< imaginary part of x-coordinate of generator point in group G2 */
extern const BIG_384_29 CURVE_Pya_BLS381; /**< real part of y-coordinate of generator point in group G2 */
extern const BIG_384_29 CURVE_Pyb_BLS381; /**< imaginary part of y-coordinate of generator point in group G2 */


/*** needed for BLS24 curves ***/

extern const BIG_384_29 CURVE_Pxaa_BLS381; /**< real part of x-coordinate of generator point in group G2 */
extern const BIG_384_29 CURVE_Pxab_BLS381; /**< imaginary part of x-coordinate of generator point in group G2 */
extern const BIG_384_29 CURVE_Pxba_BLS381; /**< real part of x-coordinate of generator point in group G2 */
extern const BIG_384_29 CURVE_Pxbb_BLS381; /**< imaginary part of x-coordinate of generator point in group G2 */
extern const BIG_384_29 CURVE_Pyaa_BLS381; /**< real part of y-coordinate of generator point in group G2 */
extern const BIG_384_29 CURVE_Pyab_BLS381; /**< imaginary part of y-coordinate of generator point in group G2 */
extern const BIG_384_29 CURVE_Pyba_BLS381; /**< real part of y-coordinate of generator point in group G2 */
extern const BIG_384_29 CURVE_Pybb_BLS381; /**< imaginary part of y-coordinate of generator point in group G2 */

/*** needed for BLS48 curves ***/

extern const BIG_384_29 CURVE_Pxaaa_BLS381; /**< real part of x-coordinate of generator point in group G2 */
extern const BIG_384_29 CURVE_Pxaab_BLS381; /**< imaginary part of x-coordinate of generator point in group G2 */
extern const BIG_384_29 CURVE_Pxaba_BLS381; /**< real part of x-coordinate of generator point in group G2 */
extern const BIG_384_29 CURVE_Pxabb_BLS381; /**< imaginary part of x-coordinate of generator point in group G2 */
extern const BIG_384_29 CURVE_Pxbaa_BLS381; /**< real part of x-coordinate of generator point in group G2 */
extern const BIG_384_29 CURVE_Pxbab_BLS381; /**< imaginary part of x-coordinate of generator point in group G2 */
extern const BIG_384_29 CURVE_Pxbba_BLS381; /**< real part of x-coordinate of generator point in group G2 */
extern const BIG_384_29 CURVE_Pxbbb_BLS381; /**< imaginary part of x-coordinate of generator point in group G2 */

extern const BIG_384_29 CURVE_Pyaaa_BLS381; /**< real part of y-coordinate of generator point in group G2 */
extern const BIG_384_29 CURVE_Pyaab_BLS381; /**< imaginary part of y-coordinate of generator point in group G2 */
extern const BIG_384_29 CURVE_Pyaba_BLS381; /**< real part of y-coordinate of generator point in group G2 */
extern const BIG_384_29 CURVE_Pyabb_BLS381; /**< imaginary part of y-coordinate of generator point in group G2 */
extern const BIG_384_29 CURVE_Pybaa_BLS381; /**< real part of y-coordinate of generator point in group G2 */
extern const BIG_384_29 CURVE_Pybab_BLS381; /**< imaginary part of y-coordinate of generator point in group G2 */
extern const BIG_384_29 CURVE_Pybba_BLS381; /**< real part of y-coordinate of generator point in group G2 */
extern const BIG_384_29 CURVE_Pybbb_BLS381; /**< imaginary part of y-coordinate of generator point in group G2 */


extern const BIG_384_29 CURVE_Bnx_BLS381; /**< BN curve x parameter */

extern const BIG_384_29 CURVE_Cru_BLS381; /**< BN curve Cube Root of Unity */

extern const BIG_384_29 Fra_BLS381; /**< real part of BN curve Frobenius Constant */
extern const BIG_384_29 Frb_BLS381; /**< imaginary part of BN curve Frobenius Constant */


extern const BIG_384_29 CURVE_W_BLS381[2];	 /**< BN curve constant for GLV decomposition */
extern const BIG_384_29 CURVE_SB_BLS381[2][2]; /**< BN curve constant for GLV decomposition */
extern const BIG_384_29 CURVE_WB_BLS381[4];	 /**< BN curve constant for GS decomposition */
extern const BIG_384_29 CURVE_BB_BLS381[4][4]; /**< BN curve constant for GS decomposition */


/**
	@brief ECP structure - Elliptic Curve Point over base field
*/

typedef struct
{
//    int inf; /**< Infinity Flag - not needed for Edwards representation */

    FP_BLS381 x; /**< x-coordinate of point */
#if CURVETYPE_BLS381!=MONTGOMERY
    FP_BLS381 y; /**< y-coordinate of point. Not needed for Montgomery representation */
#endif
    FP_BLS381 z;/**< z-coordinate of point */
} ECP_BLS381;


/* ECP E(Fp) prototypes */
/**	@brief Tests for ECP point equal to infinity
 *
	@param P ECP point to be tested
	@return 1 if infinity, else returns 0
 */
extern int ECP_BLS381_isinf(ECP_BLS381 *P);
/**	@brief Tests for equality of two ECPs
 *
	@param P ECP instance to be compared
	@param Q ECP instance to be compared
	@return 1 if P=Q, else returns 0
 */
extern int ECP_BLS381_equals(ECP_BLS381 *P,ECP_BLS381 *Q);
/**	@brief Copy ECP point to another ECP point
 *
	@param P ECP instance, on exit = Q
	@param Q ECP instance to be copied
 */
extern void ECP_BLS381_copy(ECP_BLS381 *P,ECP_BLS381 *Q);
/**	@brief Negation of an ECP point
 *
	@param P ECP instance, on exit = -P
 */
extern void ECP_BLS381_neg(ECP_BLS381 *P);
/**	@brief Set ECP to point-at-infinity
 *
	@param P ECP instance to be set to infinity
 */
extern void ECP_BLS381_inf(ECP_BLS381 *P);
/**	@brief Calculate Right Hand Side of curve equation y^2=f(x)
 *
	Function f(x) depends on form of elliptic curve, Weierstrass, Edwards or Montgomery.
	Used internally.
	@param r BIG n-residue value of f(x)
	@param x BIG n-residue x
 */
extern void ECP_BLS381_rhs(FP_BLS381 *r,FP_BLS381 *x);

#if CURVETYPE_BLS381==MONTGOMERY
/**	@brief Set ECP to point(x,[y]) given x
 *
	Point P set to infinity if no such point on the curve. Note that y coordinate is not needed.
	@param P ECP instance to be set (x,[y])
	@param x BIG x coordinate of point
	@return 1 if point exists, else 0
 */
extern int ECP_BLS381_set(ECP_BLS381 *P,BIG_384_29 x);
/**	@brief Extract x coordinate of an ECP point P
 *
	@param x BIG on exit = x coordinate of point
	@param P ECP instance (x,[y])
	@return -1 if P is point-at-infinity, else 0
 */
extern int ECP_BLS381_get(BIG_384_29 x,ECP_BLS381 *P);
/**	@brief Adds ECP instance Q to ECP instance P, given difference D=P-Q
 *
	Differential addition of points on a Montgomery curve
	@param P ECP instance, on exit =P+Q
	@param Q ECP instance to be added to P
	@param D Difference between P and Q
 */
extern void ECP_BLS381_add(ECP_BLS381 *P,ECP_BLS381 *Q,ECP_BLS381 *D);
#else
/**	@brief Set ECP to point(x,y) given x and y
 *
	Point P set to infinity if no such point on the curve.
	@param P ECP instance to be set (x,y)
	@param x BIG x coordinate of point
	@param y BIG y coordinate of point
	@return 1 if point exists, else 0
 */
extern int ECP_BLS381_set(ECP_BLS381 *P,BIG_384_29 x,BIG_384_29 y);
/**	@brief Extract x and y coordinates of an ECP point P
 *
	If x=y, returns only x
	@param x BIG on exit = x coordinate of point
	@param y BIG on exit = y coordinate of point (unless x=y)
	@param P ECP instance (x,y)
	@return sign of y, or -1 if P is point-at-infinity
 */
extern int ECP_BLS381_get(BIG_384_29 x,BIG_384_29 y,ECP_BLS381 *P);
/**	@brief Adds ECP instance Q to ECP instance P
 *
	@param P ECP instance, on exit =P+Q
	@param Q ECP instance to be added to P
 */
extern void ECP_BLS381_add(ECP_BLS381 *P,ECP_BLS381 *Q);
/**	@brief Subtracts ECP instance Q from ECP instance P
 *
	@param P ECP instance, on exit =P-Q
	@param Q ECP instance to be subtracted from P
 */
extern void ECP_BLS381_sub(ECP_BLS381 *P,ECP_BLS381 *Q);
/**	@brief Set ECP to point(x,y) given just x and sign of y
 *
	Point P set to infinity if no such point on the curve. If x is on the curve then y is calculated from the curve equation.
	The correct y value (plus or minus) is selected given its sign s.
	@param P ECP instance to be set (x,[y])
	@param x BIG x coordinate of point
	@param s an integer representing the "sign" of y, in fact its least significant bit.
 */
extern int ECP_BLS381_setx(ECP_BLS381 *P,BIG_384_29 x,int s);

#endif

/**	@brief Multiplies Point by curve co-factor
 *
	@param Q ECP instance
 */
extern void ECP_BLS381_cfp(ECP_BLS381 *Q);

/**	@brief Maps random BIG to curve point of correct order
 *
	@param Q ECP instance of correct order
	@param w OCTET byte array to be mapped
 */
extern void ECP_BLS381_mapit(ECP_BLS381 *Q,octet *w);

/**	@brief Converts an ECP point from Projective (x,y,z) coordinates to affine (x,y) coordinates
 *
	@param P ECP instance to be converted to affine form
 */
extern void ECP_BLS381_affine(ECP_BLS381 *P);
/**	@brief Formats and outputs an ECP point to the console, in projective coordinates
 *
	@param P ECP instance to be printed
 */
extern void ECP_BLS381_outputxyz(ECP_BLS381 *P);
/**	@brief Formats and outputs an ECP point to the console, converted to affine coordinates
 *
	@param P ECP instance to be printed
 */
extern void ECP_BLS381_output(ECP_BLS381 * P);

/**	@brief Formats and outputs an ECP point to the console
 *
	@param P ECP instance to be printed
 */
extern void ECP_BLS381_rawoutput(ECP_BLS381 * P);

/**	@brief Formats and outputs an ECP point to an octet string
	The octet string is normally in the standard form 0x04|x|y
	Here x (and y) are the x and y coordinates in left justified big-endian base 256 form.
	For Montgomery curve it is 0x06|x
	If c is true, only the x coordinate is provided as in 0x2|x if y is even, or 0x3|x if y is odd
	@param c compression required, true or false
	@param S output octet string
	@param P ECP instance to be converted to an octet string
 */
extern void ECP_BLS381_toOctet(octet *S,ECP_BLS381 *P,bool c);
/**	@brief Creates an ECP point from an octet string
 *
	The octet string is normally in the standard form 0x04|x|y
	Here x (and y) are the x and y coordinates in left justified big-endian base 256 form.
	For Montgomery curve it is 0x06|x
	If in compressed form only the x coordinate is provided as in 0x2|x if y is even, or 0x3|x if y is odd
	@param P ECP instance to be created from the octet string
	@param S input octet string
	return 1 if octet string corresponds to a point on the curve, else 0
 */
extern int ECP_BLS381_fromOctet(ECP_BLS381 *P,octet *S);
/**	@brief Doubles an ECP instance P
 *
	@param P ECP instance, on exit =2*P
 */
extern void ECP_BLS381_dbl(ECP_BLS381 *P);
/**	@brief Multiplies an ECP instance P by a small integer, side-channel resistant
 *
	@param P ECP instance, on exit =i*P
	@param i small integer multiplier
	@param b maximum number of bits in multiplier
 */
extern void ECP_BLS381_pinmul(ECP_BLS381 *P,int i,int b);
/**	@brief Multiplies an ECP instance P by a BIG, side-channel resistant
 *
	Uses Montgomery ladder for Montgomery curves, otherwise fixed sized windows.
	@param P ECP instance, on exit =b*P
	@param b BIG number multiplier

 */
extern void ECP_BLS381_mul(ECP_BLS381 *P,BIG_384_29 b);
/**	@brief Calculates double multiplication P=e*P+f*Q, side-channel resistant
 *
	@param P ECP instance, on exit =e*P+f*Q
	@param Q ECP instance
	@param e BIG number multiplier
	@param f BIG number multiplier
 */
extern void ECP_BLS381_mul2(ECP_BLS381 *P,ECP_BLS381 *Q,BIG_384_29 e,BIG_384_29 f);
/**	@brief Get Group Generator from ROM
 *
	@param G ECP instance
 */
extern void ECP_BLS381_generator(ECP_BLS381 *G);


#endif
