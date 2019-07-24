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
 * @file fp4_BLS381.h
 * @author Mike Scott
 * @brief FP4 Header File
 *
 */

#ifndef FP4_BLS381_H
#define FP4_BLS381_H

#include "fp2_BLS381.h"
#include "config_curve_BLS381.h"

/**
	@brief FP4 Structure - towered over two FP2
*/

typedef struct
{
    FP2_BLS381 a; /**< real part of FP4 */
    FP2_BLS381 b; /**< imaginary part of FP4 */
} FP4_BLS381;


/* FP4 prototypes */
/**	@brief Tests for FP4 equal to zero
 *
	@param x FP4 number to be tested
	@return 1 if zero, else returns 0
 */
extern int FP4_BLS381_iszilch(FP4_BLS381 *x);
/**	@brief Tests for FP4 equal to unity
 *
	@param x FP4 number to be tested
	@return 1 if unity, else returns 0
 */
extern int FP4_BLS381_isunity(FP4_BLS381 *x);
/**	@brief Tests for equality of two FP4s
 *
	@param x FP4 instance to be compared
	@param y FP4 instance to be compared
	@return 1 if x=y, else returns 0
 */
extern int FP4_BLS381_equals(FP4_BLS381 *x,FP4_BLS381 *y);
/**	@brief Tests for FP4 having only a real part and no imaginary part
 *
	@param x FP4 number to be tested
	@return 1 if real, else returns 0
 */
extern int FP4_BLS381_isreal(FP4_BLS381 *x);
/**	@brief Initialise FP4 from two FP2s
 *
	@param x FP4 instance to be initialised
	@param a FP2 to form real part of FP4
	@param b FP2 to form imaginary part of FP4
 */
extern void FP4_BLS381_from_FP2s(FP4_BLS381 *x,FP2_BLS381 *a,FP2_BLS381 *b);
/**	@brief Initialise FP4 from single FP2
 *
	Imaginary part is set to zero
	@param x FP4 instance to be initialised
	@param a FP2 to form real part of FP4
 */
extern void FP4_BLS381_from_FP2(FP4_BLS381 *x,FP2_BLS381 *a);

/**	@brief Initialise FP4 from single FP2
 *
	real part is set to zero
	@param x FP4 instance to be initialised
	@param a FP2 to form imaginary part of FP4
 */
extern void FP4_BLS381_from_FP2H(FP4_BLS381 *x,FP2_BLS381 *a);


/**	@brief Copy FP4 to another FP4
 *
	@param x FP4 instance, on exit = y
	@param y FP4 instance to be copied
 */
extern void FP4_BLS381_copy(FP4_BLS381 *x,FP4_BLS381 *y);
/**	@brief Set FP4 to zero
 *
	@param x FP4 instance to be set to zero
 */
extern void FP4_BLS381_zero(FP4_BLS381 *x);
/**	@brief Set FP4 to unity
 *
	@param x FP4 instance to be set to one
 */
extern void FP4_BLS381_one(FP4_BLS381 *x);
/**	@brief Negation of FP4
 *
	@param x FP4 instance, on exit = -y
	@param y FP4 instance
 */
extern void FP4_BLS381_neg(FP4_BLS381 *x,FP4_BLS381 *y);
/**	@brief Conjugation of FP4
 *
	If y=(a,b) on exit x=(a,-b)
	@param x FP4 instance, on exit = conj(y)
	@param y FP4 instance
 */
extern void FP4_BLS381_conj(FP4_BLS381 *x,FP4_BLS381 *y);
/**	@brief Negative conjugation of FP4
 *
	If y=(a,b) on exit x=(-a,b)
	@param x FP4 instance, on exit = -conj(y)
	@param y FP4 instance
 */
extern void FP4_BLS381_nconj(FP4_BLS381 *x,FP4_BLS381 *y);
/**	@brief addition of two FP4s
 *
	@param x FP4 instance, on exit = y+z
	@param y FP4 instance
	@param z FP4 instance
 */
extern void FP4_BLS381_add(FP4_BLS381 *x,FP4_BLS381 *y,FP4_BLS381 *z);
/**	@brief subtraction of two FP4s
 *
	@param x FP4 instance, on exit = y-z
	@param y FP4 instance
	@param z FP4 instance
 */
extern void FP4_BLS381_sub(FP4_BLS381 *x,FP4_BLS381 *y,FP4_BLS381 *z);
/**	@brief Multiplication of an FP4 by an FP2
 *
	@param x FP4 instance, on exit = y*a
	@param y FP4 instance
	@param a FP2 multiplier
 */
extern void FP4_BLS381_pmul(FP4_BLS381 *x,FP4_BLS381 *y,FP2_BLS381 *a);

/**	@brief Multiplication of an FP4 by an FP
 *
	@param x FP4 instance, on exit = y*a
	@param y FP4 instance
	@param a FP multiplier
 */
extern void FP4_BLS381_qmul(FP4_BLS381 *x,FP4_BLS381 *y,FP_BLS381 *a);

/**	@brief Multiplication of an FP4 by a small integer
 *
	@param x FP4 instance, on exit = y*i
	@param y FP4 instance
	@param i an integer
 */
extern void FP4_BLS381_imul(FP4_BLS381 *x,FP4_BLS381 *y,int i);
/**	@brief Squaring an FP4
 *
	@param x FP4 instance, on exit = y^2
	@param y FP4 instance
 */
extern void FP4_BLS381_sqr(FP4_BLS381 *x,FP4_BLS381 *y);
/**	@brief Multiplication of two FP4s
 *
	@param x FP4 instance, on exit = y*z
	@param y FP4 instance
	@param z FP4 instance
 */
extern void FP4_BLS381_mul(FP4_BLS381 *x,FP4_BLS381 *y,FP4_BLS381 *z);
/**	@brief Inverting an FP4
 *
	@param x FP4 instance, on exit = 1/y
	@param y FP4 instance
 */
extern void FP4_BLS381_inv(FP4_BLS381 *x,FP4_BLS381 *y);
/**	@brief Formats and outputs an FP4 to the console
 *
	@param x FP4 instance to be printed
 */
extern void FP4_BLS381_output(FP4_BLS381 *x);
/**	@brief Formats and outputs an FP4 to the console in raw form (for debugging)
 *
	@param x FP4 instance to be printed
 */
extern void FP4_BLS381_rawoutput(FP4_BLS381 *x);
/**	@brief multiplies an FP4 instance by irreducible polynomial sqrt(1+sqrt(-1))
 *
	@param x FP4 instance, on exit = sqrt(1+sqrt(-1)*x
 */
extern void FP4_BLS381_times_i(FP4_BLS381 *x);
/**	@brief Normalises the components of an FP4
 *
	@param x FP4 instance to be normalised
 */
extern void FP4_BLS381_norm(FP4_BLS381 *x);
/**	@brief Reduces all components of possibly unreduced FP4 mod Modulus
 *
	@param x FP4 instance, on exit reduced mod Modulus
 */
extern void FP4_BLS381_reduce(FP4_BLS381 *x);
/**	@brief Raises an FP4 to the power of a BIG
 *
	@param x FP4 instance, on exit = y^b
	@param y FP4 instance
	@param b BIG number
 */
extern void FP4_BLS381_pow(FP4_BLS381 *x,FP4_BLS381 *y,BIG_384_29 b);
/**	@brief Raises an FP4 to the power of the internal modulus p, using the Frobenius
 *
	@param x FP4 instance, on exit = x^p
	@param f FP2 precalculated Frobenius constant
 */
extern void FP4_BLS381_frob(FP4_BLS381 *x,FP2_BLS381 *f);
/**	@brief Calculates the XTR addition function r=w*x-conj(x)*y+z
 *
	@param r FP4 instance, on exit = w*x-conj(x)*y+z
	@param w FP4 instance
	@param x FP4 instance
	@param y FP4 instance
	@param z FP4 instance
 */
extern void FP4_BLS381_xtr_A(FP4_BLS381 *r,FP4_BLS381 *w,FP4_BLS381 *x,FP4_BLS381 *y,FP4_BLS381 *z);
/**	@brief Calculates the XTR doubling function r=x^2-2*conj(x)
 *
	@param r FP4 instance, on exit = x^2-2*conj(x)
	@param x FP4 instance
 */
extern void FP4_BLS381_xtr_D(FP4_BLS381 *r,FP4_BLS381 *x);
/**	@brief Calculates FP4 trace of an FP12 raised to the power of a BIG number
 *
	XTR single exponentiation
	@param r FP4 instance, on exit = trace(w^b)
	@param x FP4 instance, trace of an FP12 w
	@param b BIG number
 */
extern void FP4_BLS381_xtr_pow(FP4_BLS381 *r,FP4_BLS381 *x,BIG_384_29 b);
/**	@brief Calculates FP4 trace of c^a.d^b, where c and d are derived from FP4 traces of FP12s
 *
	XTR double exponentiation
	Assumes c=tr(x^m), d=tr(x^n), e=tr(x^(m-n)), f=tr(x^(m-2n))
	@param r FP4 instance, on exit = trace(c^a.d^b)
	@param c FP4 instance, trace of an FP12
	@param d FP4 instance, trace of an FP12
	@param e FP4 instance, trace of an FP12
	@param f FP4 instance, trace of an FP12
	@param a BIG number
	@param b BIG number
 */
extern void FP4_BLS381_xtr_pow2(FP4_BLS381 *r,FP4_BLS381 *c,FP4_BLS381 *d,FP4_BLS381 *e,FP4_BLS381 *f,BIG_384_29 a,BIG_384_29 b);

/**	@brief Conditional copy of FP4 number
 *
	Conditionally copies second parameter to the first (without branching)
	@param x FP4 instance, set to y if s!=0
	@param y another FP4 instance
	@param s copy only takes place if not equal to 0
 */
extern void FP4_BLS381_cmove(FP4_BLS381 *x,FP4_BLS381 *y,int s);


/**	@brief Calculate square root of an FP4
 *
	Square root
	@param r FP4 instance, on exit = sqrt(x)
	@param x FP4 instance
	@return 1 x is a QR, otherwise 0
 */
extern int  FP4_BLS381_sqrt(FP4_BLS381 *r,FP4_BLS381 *x);


/**	@brief Divide FP4 number by QNR
 *
	Divide FP4 by the QNR
	@param x FP4 instance
 */
extern void FP4_BLS381_div_i(FP4_BLS381 *x);

/**	@brief Divide an FP4 by QNR/2
 *
	Divide FP4 by the QNR/2
	@param x FP4 instance
 */
extern void FP4_BLS381_div_2i(FP4_BLS381 *x);



/**	@brief Divide an FP4 by 2
 *
	@param x FP4 instance, on exit = y/2
	@param y FP4 instance
 */
extern void FP4_BLS381_div2(FP4_BLS381 *x,FP4_BLS381 *y);

#endif

