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

/* AMCL Fp^12 functions */
/* SU=m, m is Stack Usage (no lazy )*/
/* FP12 elements are of the form a+i.b+i^2.c */

#include "fp12_BLS381.h"

/* return 1 if b==c, no branching */
static int teq(sign32 b,sign32 c)
{
    sign32 x=b^c;
    x-=1;  // if x=0, x now -1
    return (int)((x>>31)&1);
}


/* Constant time select from pre-computed table */
static void FP12_BLS381_select(FP12_BLS381 *f,FP12_BLS381 g[],sign32 b)
{
    FP12_BLS381 invf;
    sign32 m=b>>31;
    sign32 babs=(b^m)-m;

    babs=(babs-1)/2;

    FP12_BLS381_cmove(f,&g[0],teq(babs,0));  // conditional move
    FP12_BLS381_cmove(f,&g[1],teq(babs,1));
    FP12_BLS381_cmove(f,&g[2],teq(babs,2));
    FP12_BLS381_cmove(f,&g[3],teq(babs,3));
    FP12_BLS381_cmove(f,&g[4],teq(babs,4));
    FP12_BLS381_cmove(f,&g[5],teq(babs,5));
    FP12_BLS381_cmove(f,&g[6],teq(babs,6));
    FP12_BLS381_cmove(f,&g[7],teq(babs,7));

    FP12_BLS381_copy(&invf,f);
    FP12_BLS381_conj(&invf,&invf);  // 1/f
    FP12_BLS381_cmove(f,&invf,(int)(m&1));
}



/* test x==0 ? */
/* SU= 8 */
int FP12_BLS381_iszilch(FP12_BLS381 *x)
{
    if (FP4_BLS381_iszilch(&(x->a)) && FP4_BLS381_iszilch(&(x->b)) && FP4_BLS381_iszilch(&(x->c))) return 1;
    return 0;
}

/* test x==1 ? */
/* SU= 8 */
int FP12_BLS381_isunity(FP12_BLS381 *x)
{
    if (FP4_BLS381_isunity(&(x->a)) && FP4_BLS381_iszilch(&(x->b)) && FP4_BLS381_iszilch(&(x->c))) return 1;
    return 0;
}

/* FP12 copy w=x */
/* SU= 16 */
void FP12_BLS381_copy(FP12_BLS381 *w,FP12_BLS381 *x)
{
    if (x==w) return;
    FP4_BLS381_copy(&(w->a),&(x->a));
    FP4_BLS381_copy(&(w->b),&(x->b));
    FP4_BLS381_copy(&(w->c),&(x->c));
}

/* FP12 w=1 */
/* SU= 8 */
void FP12_BLS381_one(FP12_BLS381 *w)
{
    FP4_BLS381_one(&(w->a));
    FP4_BLS381_zero(&(w->b));
    FP4_BLS381_zero(&(w->c));
}

/* return 1 if x==y, else 0 */
/* SU= 16 */
int FP12_BLS381_equals(FP12_BLS381 *x,FP12_BLS381 *y)
{
    if (FP4_BLS381_equals(&(x->a),&(y->a)) && FP4_BLS381_equals(&(x->b),&(y->b)) && FP4_BLS381_equals(&(x->b),&(y->b)))
        return 1;
    return 0;
}

/* Set w=conj(x) */
/* SU= 8 */
void FP12_BLS381_conj(FP12_BLS381 *w,FP12_BLS381 *x)
{
    FP12_BLS381_copy(w,x);
    FP4_BLS381_conj(&(w->a),&(w->a));
    FP4_BLS381_nconj(&(w->b),&(w->b));
    FP4_BLS381_conj(&(w->c),&(w->c));
}

/* Create FP12 from FP4 */
/* SU= 8 */
void FP12_BLS381_from_FP4(FP12_BLS381 *w,FP4_BLS381 *a)
{
    FP4_BLS381_copy(&(w->a),a);
    FP4_BLS381_zero(&(w->b));
    FP4_BLS381_zero(&(w->c));
}

/* Create FP12 from 3 FP4's */
/* SU= 16 */
void FP12_BLS381_from_FP4s(FP12_BLS381 *w,FP4_BLS381 *a,FP4_BLS381 *b,FP4_BLS381 *c)
{
    FP4_BLS381_copy(&(w->a),a);
    FP4_BLS381_copy(&(w->b),b);
    FP4_BLS381_copy(&(w->c),c);
}

/* Granger-Scott Unitary Squaring. This does not benefit from lazy reduction */
/* SU= 600 */
void FP12_BLS381_usqr(FP12_BLS381 *w,FP12_BLS381 *x)
{
    FP4_BLS381 A,B,C,D;

    FP4_BLS381_copy(&A,&(x->a));

    FP4_BLS381_sqr(&(w->a),&(x->a));
    FP4_BLS381_add(&D,&(w->a),&(w->a));
    FP4_BLS381_add(&(w->a),&D,&(w->a));

    FP4_BLS381_norm(&(w->a));
    FP4_BLS381_nconj(&A,&A);

    FP4_BLS381_add(&A,&A,&A);
    FP4_BLS381_add(&(w->a),&(w->a),&A);
    FP4_BLS381_sqr(&B,&(x->c));
    FP4_BLS381_times_i(&B);

    FP4_BLS381_add(&D,&B,&B);
    FP4_BLS381_add(&B,&B,&D);
    FP4_BLS381_norm(&B);

    FP4_BLS381_sqr(&C,&(x->b));

    FP4_BLS381_add(&D,&C,&C);
    FP4_BLS381_add(&C,&C,&D);

    FP4_BLS381_norm(&C);
    FP4_BLS381_conj(&(w->b),&(x->b));
    FP4_BLS381_add(&(w->b),&(w->b),&(w->b));
    FP4_BLS381_nconj(&(w->c),&(x->c));

    FP4_BLS381_add(&(w->c),&(w->c),&(w->c));
    FP4_BLS381_add(&(w->b),&B,&(w->b));
    FP4_BLS381_add(&(w->c),&C,&(w->c));

    FP12_BLS381_reduce(w);	    /* reduce here as in pow function repeated squarings would trigger multiple reductions */
}

/* FP12 squaring w=x^2 */
/* SU= 600 */
void FP12_BLS381_sqr(FP12_BLS381 *w,FP12_BLS381 *x)
{
    /* Use Chung-Hasan SQR2 method from http://cacr.uwaterloo.ca/techreports/2006/cacr2006-24.pdf */

    FP4_BLS381 A,B,C,D;

    FP4_BLS381_sqr(&A,&(x->a));
    FP4_BLS381_mul(&B,&(x->b),&(x->c));
    FP4_BLS381_add(&B,&B,&B);
    FP4_BLS381_norm(&B);
    FP4_BLS381_sqr(&C,&(x->c));

    FP4_BLS381_mul(&D,&(x->a),&(x->b));
    FP4_BLS381_add(&D,&D,&D);
    FP4_BLS381_add(&(w->c),&(x->a),&(x->c));
    FP4_BLS381_add(&(w->c),&(x->b),&(w->c));
    FP4_BLS381_norm(&(w->c));

    FP4_BLS381_sqr(&(w->c),&(w->c));

    FP4_BLS381_copy(&(w->a),&A);
    FP4_BLS381_add(&A,&A,&B);

    FP4_BLS381_norm(&A);

    FP4_BLS381_add(&A,&A,&C);
    FP4_BLS381_add(&A,&A,&D);

    FP4_BLS381_norm(&A);
    FP4_BLS381_neg(&A,&A);
    FP4_BLS381_times_i(&B);
    FP4_BLS381_times_i(&C);

    FP4_BLS381_add(&(w->a),&(w->a),&B);
    FP4_BLS381_add(&(w->b),&C,&D);
    FP4_BLS381_add(&(w->c),&(w->c),&A);

    FP12_BLS381_norm(w);
}

/* FP12 full multiplication w=w*y */


/* SU= 896 */
/* FP12 full multiplication w=w*y */
void FP12_BLS381_mul(FP12_BLS381 *w,FP12_BLS381 *y)
{
    FP4_BLS381 z0,z1,z2,z3,t0,t1;

    FP4_BLS381_mul(&z0,&(w->a),&(y->a));
    FP4_BLS381_mul(&z2,&(w->b),&(y->b));  //

    FP4_BLS381_add(&t0,&(w->a),&(w->b));
    FP4_BLS381_add(&t1,&(y->a),&(y->b));  //

    FP4_BLS381_norm(&t0);
    FP4_BLS381_norm(&t1);

    FP4_BLS381_mul(&z1,&t0,&t1);
    FP4_BLS381_add(&t0,&(w->b),&(w->c));
    FP4_BLS381_add(&t1,&(y->b),&(y->c));  //

    FP4_BLS381_norm(&t0);
    FP4_BLS381_norm(&t1);

    FP4_BLS381_mul(&z3,&t0,&t1);

    FP4_BLS381_neg(&t0,&z0);
    FP4_BLS381_neg(&t1,&z2);

    FP4_BLS381_add(&z1,&z1,&t0);   // z1=z1-z0
//    FP4_BLS381_norm(&z1);
    FP4_BLS381_add(&(w->b),&z1,&t1);
// z1=z1-z2
    FP4_BLS381_add(&z3,&z3,&t1);        // z3=z3-z2
    FP4_BLS381_add(&z2,&z2,&t0);        // z2=z2-z0

    FP4_BLS381_add(&t0,&(w->a),&(w->c));
    FP4_BLS381_add(&t1,&(y->a),&(y->c));

    FP4_BLS381_norm(&t0);
    FP4_BLS381_norm(&t1);

    FP4_BLS381_mul(&t0,&t1,&t0);
    FP4_BLS381_add(&z2,&z2,&t0);

    FP4_BLS381_mul(&t0,&(w->c),&(y->c));
    FP4_BLS381_neg(&t1,&t0);

    FP4_BLS381_add(&(w->c),&z2,&t1);
    FP4_BLS381_add(&z3,&z3,&t1);
    FP4_BLS381_times_i(&t0);
    FP4_BLS381_add(&(w->b),&(w->b),&t0);
    FP4_BLS381_norm(&z3);
    FP4_BLS381_times_i(&z3);
    FP4_BLS381_add(&(w->a),&z0,&z3);

    FP12_BLS381_norm(w);
}

/* FP12 multiplication w=w*y */
/* SU= 744 */
/* catering for special case that arises from special form of ATE pairing line function */
void FP12_BLS381_smul(FP12_BLS381 *w,FP12_BLS381 *y,int type)
{
    FP4_BLS381 z0,z1,z2,z3,t0,t1;

    if (type==D_TYPE)
    {
        // y->c is 0

        FP4_BLS381_copy(&z3,&(w->b));
        FP4_BLS381_mul(&z0,&(w->a),&(y->a));

        FP4_BLS381_pmul(&z2,&(w->b),&(y->b).a);
        FP4_BLS381_add(&(w->b),&(w->a),&(w->b));
        FP4_BLS381_copy(&t1,&(y->a));
        FP2_BLS381_add(&t1.a,&t1.a,&(y->b).a);

        FP4_BLS381_norm(&t1);
        FP4_BLS381_norm(&(w->b));

        FP4_BLS381_mul(&(w->b),&(w->b),&t1);
        FP4_BLS381_add(&z3,&z3,&(w->c));
        FP4_BLS381_norm(&z3);
        FP4_BLS381_pmul(&z3,&z3,&(y->b).a);
        FP4_BLS381_neg(&t0,&z0);
        FP4_BLS381_neg(&t1,&z2);

        FP4_BLS381_add(&(w->b),&(w->b),&t0);   // z1=z1-z0
//    FP4_BLS381_norm(&(w->b));
        FP4_BLS381_add(&(w->b),&(w->b),&t1);   // z1=z1-z2

        FP4_BLS381_add(&z3,&z3,&t1);        // z3=z3-z2
        FP4_BLS381_add(&z2,&z2,&t0);        // z2=z2-z0

        FP4_BLS381_add(&t0,&(w->a),&(w->c));

        FP4_BLS381_norm(&t0);
        FP4_BLS381_norm(&z3);

        FP4_BLS381_mul(&t0,&(y->a),&t0);
        FP4_BLS381_add(&(w->c),&z2,&t0);

        FP4_BLS381_times_i(&z3);
        FP4_BLS381_add(&(w->a),&z0,&z3);
    }

    if (type==M_TYPE)
    {
        // y->b is zero
        FP4_BLS381_mul(&z0,&(w->a),&(y->a));
        FP4_BLS381_add(&t0,&(w->a),&(w->b));
        FP4_BLS381_norm(&t0);

        FP4_BLS381_mul(&z1,&t0,&(y->a));
        FP4_BLS381_add(&t0,&(w->b),&(w->c));
        FP4_BLS381_norm(&t0);

        FP4_BLS381_pmul(&z3,&t0,&(y->c).b);
        FP4_BLS381_times_i(&z3);

        FP4_BLS381_neg(&t0,&z0);
        FP4_BLS381_add(&z1,&z1,&t0);   // z1=z1-z0

        FP4_BLS381_copy(&(w->b),&z1);

        FP4_BLS381_copy(&z2,&t0);

        FP4_BLS381_add(&t0,&(w->a),&(w->c));
        FP4_BLS381_add(&t1,&(y->a),&(y->c));

        FP4_BLS381_norm(&t0);
        FP4_BLS381_norm(&t1);

        FP4_BLS381_mul(&t0,&t1,&t0);
        FP4_BLS381_add(&z2,&z2,&t0);

        FP4_BLS381_pmul(&t0,&(w->c),&(y->c).b);
        FP4_BLS381_times_i(&t0);
        FP4_BLS381_neg(&t1,&t0);
        FP4_BLS381_times_i(&t0);

        FP4_BLS381_add(&(w->c),&z2,&t1);
        FP4_BLS381_add(&z3,&z3,&t1);

        FP4_BLS381_add(&(w->b),&(w->b),&t0);
        FP4_BLS381_norm(&z3);
        FP4_BLS381_times_i(&z3);
        FP4_BLS381_add(&(w->a),&z0,&z3);
    }
    FP12_BLS381_norm(w);
}

/* Set w=1/x */
/* SU= 600 */
void FP12_BLS381_inv(FP12_BLS381 *w,FP12_BLS381 *x)
{
    FP4_BLS381 f0,f1,f2,f3;
//    FP12_BLS381_norm(x);

    FP4_BLS381_sqr(&f0,&(x->a));
    FP4_BLS381_mul(&f1,&(x->b),&(x->c));
    FP4_BLS381_times_i(&f1);
    FP4_BLS381_sub(&f0,&f0,&f1);  /* y.a */
    FP4_BLS381_norm(&f0);

    FP4_BLS381_sqr(&f1,&(x->c));
    FP4_BLS381_times_i(&f1);
    FP4_BLS381_mul(&f2,&(x->a),&(x->b));
    FP4_BLS381_sub(&f1,&f1,&f2);  /* y.b */
    FP4_BLS381_norm(&f1);

    FP4_BLS381_sqr(&f2,&(x->b));
    FP4_BLS381_mul(&f3,&(x->a),&(x->c));
    FP4_BLS381_sub(&f2,&f2,&f3);  /* y.c */
    FP4_BLS381_norm(&f2);

    FP4_BLS381_mul(&f3,&(x->b),&f2);
    FP4_BLS381_times_i(&f3);
    FP4_BLS381_mul(&(w->a),&f0,&(x->a));
    FP4_BLS381_add(&f3,&(w->a),&f3);
    FP4_BLS381_mul(&(w->c),&f1,&(x->c));
    FP4_BLS381_times_i(&(w->c));

    FP4_BLS381_add(&f3,&(w->c),&f3);
    FP4_BLS381_norm(&f3);

    FP4_BLS381_inv(&f3,&f3);

    FP4_BLS381_mul(&(w->a),&f0,&f3);
    FP4_BLS381_mul(&(w->b),&f1,&f3);
    FP4_BLS381_mul(&(w->c),&f2,&f3);

}

/* constant time powering by small integer of max length bts */

void FP12_BLS381_pinpow(FP12_BLS381 *r,int e,int bts)
{
    int i,b;
    FP12_BLS381 R[2];

    FP12_BLS381_one(&R[0]);
    FP12_BLS381_copy(&R[1],r);

    for (i=bts-1; i>=0; i--)
    {
        b=(e>>i)&1;
        FP12_BLS381_mul(&R[1-b],&R[b]);
        FP12_BLS381_usqr(&R[b],&R[b]);
    }
    FP12_BLS381_copy(r,&R[0]);
}

/* Compressed powering of unitary elements y=x^(e mod r) */

void FP12_BLS381_compow(FP4_BLS381 *c,FP12_BLS381 *x,BIG_384_58 e,BIG_384_58 r)
{
    FP12_BLS381 g1,g2;
    FP4_BLS381 cp,cpm1,cpm2;
    FP2_BLS381 f;
    BIG_384_58 q,a,b,m;

    BIG_384_58_rcopy(a,Fra_BLS381);
    BIG_384_58_rcopy(b,Frb_BLS381);
    FP2_BLS381_from_BIGs(&f,a,b);

    BIG_384_58_rcopy(q,Modulus_BLS381);

    FP12_BLS381_copy(&g1,x);
    FP12_BLS381_copy(&g2,x);

    BIG_384_58_copy(m,q);
    BIG_384_58_mod(m,r);

    BIG_384_58_copy(a,e);
    BIG_384_58_mod(a,m);

    BIG_384_58_copy(b,e);
    BIG_384_58_sdiv(b,m);

    FP12_BLS381_trace(c,&g1);

    if (BIG_384_58_iszilch(b))
    {
        FP4_BLS381_xtr_pow(c,c,e);
        return;
    }


    FP12_BLS381_frob(&g2,&f);
    FP12_BLS381_trace(&cp,&g2);

    FP12_BLS381_conj(&g1,&g1);
    FP12_BLS381_mul(&g2,&g1);
    FP12_BLS381_trace(&cpm1,&g2);
    FP12_BLS381_mul(&g2,&g1);
    FP12_BLS381_trace(&cpm2,&g2);

    FP4_BLS381_xtr_pow2(c,&cp,c,&cpm1,&cpm2,a,b);

}


/* SU= 528 */
/* set r=a^b */
/* Note this is simple square and multiply, so not side-channel safe */

void FP12_BLS381_pow(FP12_BLS381 *r,FP12_BLS381 *a,BIG_384_58 b)
{
    FP12_BLS381 w,sf;
    BIG_384_58 b1,b3;
    int i,nb,bt;
	BIG_384_58_copy(b1,b);
    BIG_384_58_norm(b1);
    BIG_384_58_pmul(b3,b1,3);
    BIG_384_58_norm(b3);

	FP12_BLS381_copy(&sf,a);
	FP12_BLS381_norm(&sf);
    FP12_BLS381_copy(&w,&sf);


    nb=BIG_384_58_nbits(b3);
    for (i=nb-2; i>=1; i--)
    {
        FP12_BLS381_usqr(&w,&w);
        bt=BIG_384_58_bit(b3,i)-BIG_384_58_bit(b1,i);
        if (bt==1)
            FP12_BLS381_mul(&w,&sf);
        if (bt==-1)
        {
            FP12_BLS381_conj(&sf,&sf);
            FP12_BLS381_mul(&w,&sf);
            FP12_BLS381_conj(&sf,&sf);
        }
    }

    FP12_BLS381_copy(r,&w);
    FP12_BLS381_reduce(r);

    /*
        while(1)
        {
            bt=BIG_384_58_parity(z);
            BIG_384_58_shr(z,1);
            if (bt)
                FP12_BLS381_mul(r,&w);
            if (BIG_384_58_comp(z,zilch)==0) break;
            FP12_BLS381_usqr(&w,&w);
        }

        FP12_BLS381_reduce(r); */
}

/* p=q0^u0.q1^u1.q2^u2.q3^u3 */
/* Side channel attack secure */
// Bos & Costello https://eprint.iacr.org/2013/458.pdf
// Faz-Hernandez & Longa & Sanchez  https://eprint.iacr.org/2013/158.pdf

void FP12_BLS381_pow4(FP12_BLS381 *p,FP12_BLS381 *q,BIG_384_58 u[4])
{
    int i,j,k,nb,pb,bt;
	FP12_BLS381 g[8],r;
	BIG_384_58 t[4],mt;
    sign8 w[NLEN_384_58*BASEBITS_384_58+1];
    sign8 s[NLEN_384_58*BASEBITS_384_58+1];

    for (i=0; i<4; i++)
        BIG_384_58_copy(t[i],u[i]);


// Precomputed table
    FP12_BLS381_copy(&g[0],&q[0]); // q[0]
    FP12_BLS381_copy(&g[1],&g[0]);
	FP12_BLS381_mul(&g[1],&q[1]);	// q[0].q[1]
    FP12_BLS381_copy(&g[2],&g[0]);
	FP12_BLS381_mul(&g[2],&q[2]);	// q[0].q[2]
	FP12_BLS381_copy(&g[3],&g[1]);
	FP12_BLS381_mul(&g[3],&q[2]);	// q[0].q[1].q[2]
	FP12_BLS381_copy(&g[4],&g[0]);
	FP12_BLS381_mul(&g[4],&q[3]);  // q[0].q[3]
	FP12_BLS381_copy(&g[5],&g[1]);
	FP12_BLS381_mul(&g[5],&q[3]);	// q[0].q[1].q[3]
	FP12_BLS381_copy(&g[6],&g[2]);
	FP12_BLS381_mul(&g[6],&q[3]);	// q[0].q[2].q[3]
	FP12_BLS381_copy(&g[7],&g[3]);
	FP12_BLS381_mul(&g[7],&q[3]);	// q[0].q[1].q[2].q[3]

// Make it odd
	pb=1-BIG_384_58_parity(t[0]);
	BIG_384_58_inc(t[0],pb);
	BIG_384_58_norm(t[0]);

// Number of bits
    BIG_384_58_zero(mt);
    for (i=0; i<4; i++)
    {
        BIG_384_58_or(mt,mt,t[i]);
    }
    nb=1+BIG_384_58_nbits(mt);

// Sign pivot 
	s[nb-1]=1;
	for (i=0;i<nb-1;i++)
	{
        BIG_384_58_fshr(t[0],1);
		s[i]=2*BIG_384_58_parity(t[0])-1;
	}

// Recoded exponent
    for (i=0; i<nb; i++)
    {
		w[i]=0;
		k=1;
		for (j=1; j<4; j++)
		{
			bt=s[i]*BIG_384_58_parity(t[j]);
			BIG_384_58_fshr(t[j],1);

			BIG_384_58_dec(t[j],(bt>>1));
			BIG_384_58_norm(t[j]);
			w[i]+=bt*k;
			k*=2;
        }
    }		

// Main loop
	FP12_BLS381_select(p,g,2*w[nb-1]+1);
    for (i=nb-2; i>=0; i--)
    {
        FP12_BLS381_select(&r,g,2*w[i]+s[i]);
		FP12_BLS381_usqr(p,p);
        FP12_BLS381_mul(p,&r);
    }
// apply correction
	FP12_BLS381_conj(&r,&q[0]);   
	FP12_BLS381_mul(&r,p);
	FP12_BLS381_cmove(p,&r,pb);

	FP12_BLS381_reduce(p);
}

/* p=q0^u0.q1^u1.q2^u2.q3^u3 */
/* Timing attack secure, but not cache attack secure */
/*
void FP12_BLS381_pow4(FP12_BLS381 *p,FP12_BLS381 *q,BIG_384_58 u[4])
{
    int i,j,a[4],nb,m;
    FP12_BLS381 g[8],c,s[2];
    BIG_384_58 t[4],mt;
    sign8 w[NLEN_384_58*BASEBITS_384_58+1];

    for (i=0; i<4; i++)
        BIG_384_58_copy(t[i],u[i]);

    FP12_BLS381_copy(&g[0],&q[0]);
    FP12_BLS381_conj(&s[0],&q[1]);
    FP12_BLS381_mul(&g[0],&s[0]);  // P/Q 
    FP12_BLS381_copy(&g[1],&g[0]);
    FP12_BLS381_copy(&g[2],&g[0]);
    FP12_BLS381_copy(&g[3],&g[0]);
    FP12_BLS381_copy(&g[4],&q[0]);
    FP12_BLS381_mul(&g[4],&q[1]);  // P*Q 
    FP12_BLS381_copy(&g[5],&g[4]);
    FP12_BLS381_copy(&g[6],&g[4]);
    FP12_BLS381_copy(&g[7],&g[4]);

    FP12_BLS381_copy(&s[1],&q[2]);
    FP12_BLS381_conj(&s[0],&q[3]);
    FP12_BLS381_mul(&s[1],&s[0]);       // R/S 
    FP12_BLS381_conj(&s[0],&s[1]);
    FP12_BLS381_mul(&g[1],&s[0]);
    FP12_BLS381_mul(&g[2],&s[1]);
    FP12_BLS381_mul(&g[5],&s[0]);
    FP12_BLS381_mul(&g[6],&s[1]);
    FP12_BLS381_copy(&s[1],&q[2]);
    FP12_BLS381_mul(&s[1],&q[3]);      // R*S 
    FP12_BLS381_conj(&s[0],&s[1]);
    FP12_BLS381_mul(&g[0],&s[0]);
    FP12_BLS381_mul(&g[3],&s[1]);
    FP12_BLS381_mul(&g[4],&s[0]);
    FP12_BLS381_mul(&g[7],&s[1]);

    // if power is even add 1 to power, and add q to correction 
    FP12_BLS381_one(&c);

    BIG_384_58_zero(mt);
    for (i=0; i<4; i++)
    {
        if (BIG_384_58_parity(t[i])==0)
        {
            BIG_384_58_inc(t[i],1);
            BIG_384_58_norm(t[i]);
            FP12_BLS381_mul(&c,&q[i]);
        }
        BIG_384_58_add(mt,mt,t[i]);
        BIG_384_58_norm(mt);
    }

    FP12_BLS381_conj(&c,&c);
    nb=1+BIG_384_58_nbits(mt);

    // convert exponent to signed 1-bit window 
    for (j=0; j<nb; j++)
    {
        for (i=0; i<4; i++)
        {
            a[i]=BIG_384_58_lastbits(t[i],2)-2;
            BIG_384_58_dec(t[i],a[i]);
            BIG_384_58_norm(t[i]);
            BIG_384_58_fshr(t[i],1);
        }
        w[j]=8*a[0]+4*a[1]+2*a[2]+a[3];
    }
    w[nb]=8*BIG_384_58_lastbits(t[0],2)+4*BIG_384_58_lastbits(t[1],2)+2*BIG_384_58_lastbits(t[2],2)+BIG_384_58_lastbits(t[3],2);
    FP12_BLS381_copy(p,&g[(w[nb]-1)/2]);

    for (i=nb-1; i>=0; i--)
    {
        m=w[i]>>7;
        j=(w[i]^m)-m;  // j=abs(w[i]) 
        j=(j-1)/2;
        FP12_BLS381_copy(&s[0],&g[j]);
        FP12_BLS381_conj(&s[1],&g[j]);
        FP12_BLS381_usqr(p,p);
        FP12_BLS381_mul(p,&s[m&1]);
    }
    FP12_BLS381_mul(p,&c); // apply correction 
    FP12_BLS381_reduce(p);
}
*/
/* Set w=w^p using Frobenius */
/* SU= 160 */
void FP12_BLS381_frob(FP12_BLS381 *w,FP2_BLS381 *f)
{
    FP2_BLS381 f2,f3;
    FP2_BLS381_sqr(&f2,f);     /* f2=f^2 */
    FP2_BLS381_mul(&f3,&f2,f); /* f3=f^3 */

    FP4_BLS381_frob(&(w->a),&f3);
    FP4_BLS381_frob(&(w->b),&f3);
    FP4_BLS381_frob(&(w->c),&f3);

    FP4_BLS381_pmul(&(w->b),&(w->b),f);
    FP4_BLS381_pmul(&(w->c),&(w->c),&f2);
}

/* SU= 8 */
/* normalise all components of w */
void FP12_BLS381_norm(FP12_BLS381 *w)
{
    FP4_BLS381_norm(&(w->a));
    FP4_BLS381_norm(&(w->b));
    FP4_BLS381_norm(&(w->c));
}

/* SU= 8 */
/* reduce all components of w */
void FP12_BLS381_reduce(FP12_BLS381 *w)
{
    FP4_BLS381_reduce(&(w->a));
    FP4_BLS381_reduce(&(w->b));
    FP4_BLS381_reduce(&(w->c));
}

/* trace function w=trace(x) */
/* SU= 8 */
void FP12_BLS381_trace(FP4_BLS381 *w,FP12_BLS381 *x)
{
    FP4_BLS381_imul(w,&(x->a),3);
    FP4_BLS381_reduce(w);
}

/* SU= 8 */
/* Output w in hex */
void FP12_BLS381_output(FP12_BLS381 *w)
{
    printf("[");
    FP4_BLS381_output(&(w->a));
    printf(",");
    FP4_BLS381_output(&(w->b));
    printf(",");
    FP4_BLS381_output(&(w->c));
    printf("]");
}

/* SU= 64 */
/* Convert g to octet string w */
void FP12_BLS381_toOctet(octet *W,FP12_BLS381 *g)
{
    BIG_384_58 a;
    W->len=12*MODBYTES_384_58;

    FP_BLS381_redc(a,&(g->a.a.a));
    BIG_384_58_toBytes(&(W->val[0]),a);
    FP_BLS381_redc(a,&(g->a.a.b));
    BIG_384_58_toBytes(&(W->val[MODBYTES_384_58]),a);
    FP_BLS381_redc(a,&(g->a.b.a));
    BIG_384_58_toBytes(&(W->val[2*MODBYTES_384_58]),a);
    FP_BLS381_redc(a,&(g->a.b.b));
    BIG_384_58_toBytes(&(W->val[3*MODBYTES_384_58]),a);
    FP_BLS381_redc(a,&(g->b.a.a));
    BIG_384_58_toBytes(&(W->val[4*MODBYTES_384_58]),a);
    FP_BLS381_redc(a,&(g->b.a.b));
    BIG_384_58_toBytes(&(W->val[5*MODBYTES_384_58]),a);
    FP_BLS381_redc(a,&(g->b.b.a));
    BIG_384_58_toBytes(&(W->val[6*MODBYTES_384_58]),a);
    FP_BLS381_redc(a,&(g->b.b.b));
    BIG_384_58_toBytes(&(W->val[7*MODBYTES_384_58]),a);
    FP_BLS381_redc(a,&(g->c.a.a));
    BIG_384_58_toBytes(&(W->val[8*MODBYTES_384_58]),a);
    FP_BLS381_redc(a,&(g->c.a.b));
    BIG_384_58_toBytes(&(W->val[9*MODBYTES_384_58]),a);
    FP_BLS381_redc(a,&(g->c.b.a));
    BIG_384_58_toBytes(&(W->val[10*MODBYTES_384_58]),a);
    FP_BLS381_redc(a,&(g->c.b.b));
    BIG_384_58_toBytes(&(W->val[11*MODBYTES_384_58]),a);
}

/* SU= 24 */
/* Restore g from octet string w */
void FP12_BLS381_fromOctet(FP12_BLS381 *g,octet *W)
{
    BIG_384_58 b;
    BIG_384_58_fromBytes(b,&W->val[0]);
    FP_BLS381_nres(&(g->a.a.a),b);
    BIG_384_58_fromBytes(b,&W->val[MODBYTES_384_58]);
    FP_BLS381_nres(&(g->a.a.b),b);
    BIG_384_58_fromBytes(b,&W->val[2*MODBYTES_384_58]);
    FP_BLS381_nres(&(g->a.b.a),b);
    BIG_384_58_fromBytes(b,&W->val[3*MODBYTES_384_58]);
    FP_BLS381_nres(&(g->a.b.b),b);
    BIG_384_58_fromBytes(b,&W->val[4*MODBYTES_384_58]);
    FP_BLS381_nres(&(g->b.a.a),b);
    BIG_384_58_fromBytes(b,&W->val[5*MODBYTES_384_58]);
    FP_BLS381_nres(&(g->b.a.b),b);
    BIG_384_58_fromBytes(b,&W->val[6*MODBYTES_384_58]);
    FP_BLS381_nres(&(g->b.b.a),b);
    BIG_384_58_fromBytes(b,&W->val[7*MODBYTES_384_58]);
    FP_BLS381_nres(&(g->b.b.b),b);
    BIG_384_58_fromBytes(b,&W->val[8*MODBYTES_384_58]);
    FP_BLS381_nres(&(g->c.a.a),b);
    BIG_384_58_fromBytes(b,&W->val[9*MODBYTES_384_58]);
    FP_BLS381_nres(&(g->c.a.b),b);
    BIG_384_58_fromBytes(b,&W->val[10*MODBYTES_384_58]);
    FP_BLS381_nres(&(g->c.b.a),b);
    BIG_384_58_fromBytes(b,&W->val[11*MODBYTES_384_58]);
    FP_BLS381_nres(&(g->c.b.b),b);
}

/* Move b to a if d=1 */
void FP12_BLS381_cmove(FP12_BLS381 *f,FP12_BLS381 *g,int d)
{
    FP4_BLS381_cmove(&(f->a),&(g->a),d);
    FP4_BLS381_cmove(&(f->b),&(g->b),d);
    FP4_BLS381_cmove(&(f->c),&(g->c),d);
}


/*
int main(){
		FP2_BLS381 f,w0,w1;
		FP4_BLS381 t0,t1,t2;
		FP12_BLS381 w,t,lv;
		BIG_384_58 a,b;
		BIG_384_58 p;

		//Test w^(P^4) = w mod p^2
//		BIG_384_58_randomnum(a);
//		BIG_384_58_randomnum(b);
//		BIG_384_58_mod(a,Modulus); BIG_384_58_mod(b,Modulus);
	BIG_384_58_zero(a); BIG_384_58_zero(b); BIG_384_58_inc(a,1); BIG_384_58_inc(b,2); FP_BLS381_nres(a); FP_BLS381_nres(b);
		FP2_BLS381_from_zps(&w0,a,b);

//		BIG_384_58_randomnum(a); BIG_384_58_randomnum(b);
//		BIG_384_58_mod(a,Modulus); BIG_384_58_mod(b,Modulus);
	BIG_384_58_zero(a); BIG_384_58_zero(b); BIG_384_58_inc(a,3); BIG_384_58_inc(b,4); FP_BLS381_nres(a); FP_BLS381_nres(b);
		FP2_BLS381_from_zps(&w1,a,b);

		FP4_BLS381_from_FP2s(&t0,&w0,&w1);
		FP4_BLS381_reduce(&t0);

//		BIG_384_58_randomnum(a);
//		BIG_384_58_randomnum(b);
//		BIG_384_58_mod(a,Modulus); BIG_384_58_mod(b,Modulus);
		BIG_384_58_zero(a); BIG_384_58_zero(b); BIG_384_58_inc(a,5); BIG_384_58_inc(b,6); FP_BLS381_nres(a); FP_BLS381_nres(b);
		FP2_BLS381_from_zps(&w0,a,b);

//		BIG_384_58_randomnum(a); BIG_384_58_randomnum(b);
//		BIG_384_58_mod(a,Modulus); BIG_384_58_mod(b,Modulus);

		BIG_384_58_zero(a); BIG_384_58_zero(b); BIG_384_58_inc(a,7); BIG_384_58_inc(b,8); FP_BLS381_nres(a); FP_BLS381_nres(b);
		FP2_BLS381_from_zps(&w1,a,b);

		FP4_BLS381_from_FP2s(&t1,&w0,&w1);
		FP4_BLS381_reduce(&t1);

//		BIG_384_58_randomnum(a);
//		BIG_384_58_randomnum(b);
//		BIG_384_58_mod(a,Modulus); BIG_384_58_mod(b,Modulus);
		BIG_384_58_zero(a); BIG_384_58_zero(b); BIG_384_58_inc(a,9); BIG_384_58_inc(b,10); FP_BLS381_nres(a); FP_BLS381_nres(b);
		FP2_BLS381_from_zps(&w0,a,b);

//		BIG_384_58_randomnum(a); BIG_384_58_randomnum(b);
//		BIG_384_58_mod(a,Modulus); BIG_384_58_mod(b,Modulus);
		BIG_384_58_zero(a); BIG_384_58_zero(b); BIG_384_58_inc(a,11); BIG_384_58_inc(b,12); FP_BLS381_nres(a); FP_BLS381_nres(b);
		FP2_BLS381_from_zps(&w1,a,b);

		FP4_BLS381_from_FP2s(&t2,&w0,&w1);
		FP4_BLS381_reduce(&t2);

		FP12_BLS381_from_FP4s(&w,&t0,&t1,&t2);

		FP12_BLS381_copy(&t,&w);

		printf("w= ");
		FP12_BLS381_output(&w);
		printf("\n");

		BIG_384_58_rcopy(p,Modulus);
		//BIG_384_58_zero(p); BIG_384_58_inc(p,7);

		FP12_BLS381_pow(&w,&w,p);

		printf("w^p= ");
		FP12_BLS381_output(&w);
		printf("\n");

		FP2_BLS381_gfc(&f,12);
		FP12_BLS381_frob(&t,&f);
		printf("w^p= ");
		FP12_BLS381_output(&t);
		printf("\n");

//exit(0);

		FP12_BLS381_pow(&w,&w,p);
		//printf("w^p^2= ");
		//FP12_BLS381_output(&w);
		//printf("\n");
		FP12_BLS381_pow(&w,&w,p);
		//printf("w^p^3= ");
		//FP12_BLS381_output(&w);
		//printf("\n");
		FP12_BLS381_pow(&w,&w,p);
		FP12_BLS381_pow(&w,&w,p);
		FP12_BLS381_pow(&w,&w,p);
		printf("w^p^6= ");
		FP12_BLS381_output(&w);
		printf("\n");
		FP12_BLS381_pow(&w,&w,p);
		FP12_BLS381_pow(&w,&w,p);
		printf("w^p^8= ");
		FP12_BLS381_output(&w);
		printf("\n");
		FP12_BLS381_pow(&w,&w,p);
		FP12_BLS381_pow(&w,&w,p);
		FP12_BLS381_pow(&w,&w,p);
		printf("w^p^11= ");
		FP12_BLS381_output(&w);
		printf("\n");

	//	BIG_384_58_zero(p); BIG_384_58_inc(p,7); BIG_384_58_norm(p);
		FP12_BLS381_pow(&w,&w,p);

		printf("w^p12= ");
		FP12_BLS381_output(&w);
		printf("\n");
//exit(0);

		FP12_BLS381_inv(&t,&w);
		printf("1/w mod p^4 = ");
		FP12_BLS381_output(&t);
		printf("\n");

		FP12_BLS381_inv(&w,&t);
		printf("1/(1/w) mod p^4 = ");
		FP12_BLS381_output(&w);
		printf("\n");



	FP12_BLS381_inv(&lv,&w);
//printf("w= "); FP12_BLS381_output(&w); printf("\n");
	FP12_BLS381_conj(&w,&w);
//printf("w= "); FP12_BLS381_output(&w); printf("\n");
//exit(0);
	FP12_BLS381_mul(&w,&w,&lv);
//printf("w= "); FP12_BLS381_output(&w); printf("\n");
	FP12_BLS381_copy(&lv,&w);
	FP12_BLS381_frob(&w,&f);
	FP12_BLS381_frob(&w,&f);
	FP12_BLS381_mul(&w,&w,&lv);

//printf("w= "); FP12_BLS381_output(&w); printf("\n");
//exit(0);

w.unitary=0;
FP12_BLS381_conj(&lv,&w);
	printf("rx= "); FP12_BLS381_output(&lv); printf("\n");
FP12_BLS381_inv(&lv,&w);
	printf("ry= "); FP12_BLS381_output(&lv); printf("\n");


		return 0;
}

*/
