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

/* AMCL mod p functions */
/* Small Finite Field arithmetic */
/* SU=m, SU is Stack Usage (NOT_SPECIAL Modulus) */

#include "fp_BLS381.h"

/* Fast Modular Reduction Methods */

/* r=d mod m */
/* d MUST be normalised */
/* Products must be less than pR in all cases !!! */
/* So when multiplying two numbers, their product *must* be less than MODBITS+BASEBITS*NLEN */
/* Results *may* be one bit bigger than MODBITS */

#if MODTYPE_BLS381 == PSEUDO_MERSENNE
/* r=d mod m */

/* Converts from BIG integer to residue form mod Modulus */
void FP_BLS381_nres(FP_BLS381 *y,BIG_384_29 x)
{
    BIG_384_29_copy(y->g,x);
    y->XES=1;
}

/* Converts from residue form back to BIG integer form */
void FP_BLS381_redc(BIG_384_29 x,FP_BLS381 *y)
{
    BIG_384_29_copy(x,y->g);
}

/* reduce a DBIG to a BIG exploiting the special form of the modulus */
void FP_BLS381_mod(BIG_384_29 r,DBIG_384_29 d)
{
    BIG_384_29 t,b;
    chunk v,tw;
    BIG_384_29_split(t,b,d,MODBITS_BLS381);

    /* Note that all of the excess gets pushed into t. So if squaring a value with a 4-bit excess, this results in
       t getting all 8 bits of the excess product! So products must be less than pR which is Montgomery compatible */

    if (MConst_BLS381 < NEXCESS_384_29)
    {
        BIG_384_29_imul(t,t,MConst_BLS381);
        BIG_384_29_norm(t);
        BIG_384_29_add(r,t,b);
        BIG_384_29_norm(r);
        tw=r[NLEN_384_29-1];
        r[NLEN_384_29-1]&=TMASK_BLS381;
        r[0]+=MConst_BLS381*((tw>>TBITS_BLS381));
    }
    else
    {
        v=BIG_384_29_pmul(t,t,MConst_BLS381);
        BIG_384_29_add(r,t,b);
        BIG_384_29_norm(r);
        tw=r[NLEN_384_29-1];
        r[NLEN_384_29-1]&=TMASK_BLS381;
#if CHUNK == 16
        r[1]+=muladd_384_29(MConst_BLS381,((tw>>TBITS_BLS381)+(v<<(BASEBITS_384_29-TBITS_BLS381))),0,&r[0]);
#else
        r[0]+=MConst_BLS381*((tw>>TBITS_BLS381)+(v<<(BASEBITS_384_29-TBITS_BLS381)));
#endif
    }
    BIG_384_29_norm(r);
}
#endif

/* This only applies to Curve C448, so specialised (for now) */
#if MODTYPE_BLS381 == GENERALISED_MERSENNE

void FP_BLS381_nres(FP_BLS381 *y,BIG_384_29 x)
{
    BIG_384_29_copy(y->g,x);
    y->XES=1;
}

/* Converts from residue form back to BIG integer form */
void FP_BLS381_redc(BIG_384_29 x,FP_BLS381 *y)
{
    BIG_384_29_copy(x,y->g);
}

/* reduce a DBIG to a BIG exploiting the special form of the modulus */
void FP_BLS381_mod(BIG_384_29 r,DBIG_384_29 d)
{
    BIG_384_29 t,b;
    chunk carry;
    BIG_384_29_split(t,b,d,MBITS_BLS381);

    BIG_384_29_add(r,t,b);

    BIG_384_29_dscopy(d,t);
    BIG_384_29_dshl(d,MBITS_BLS381/2);

    BIG_384_29_split(t,b,d,MBITS_BLS381);

    BIG_384_29_add(r,r,t);
    BIG_384_29_add(r,r,b);
    BIG_384_29_norm(r);
    BIG_384_29_shl(t,MBITS_BLS381/2);

    BIG_384_29_add(r,r,t);

    carry=r[NLEN_384_29-1]>>TBITS_BLS381;

    r[NLEN_384_29-1]&=TMASK_BLS381;
    r[0]+=carry;

    r[224/BASEBITS_384_29]+=carry<<(224%BASEBITS_384_29); /* need to check that this falls mid-word */
    BIG_384_29_norm(r);
}

#endif

#if MODTYPE_BLS381 == MONTGOMERY_FRIENDLY

/* convert to Montgomery n-residue form */
void FP_BLS381_nres(FP_BLS381 *y,BIG_384_29 x)
{
    DBIG_384_29 d;
    BIG_384_29 r;
    BIG_384_29_rcopy(r,R2modp_BLS381);
    BIG_384_29_mul(d,x,r);
    FP_BLS381_mod(y->g,d);
    y->XES=2;
}

/* convert back to regular form */
void FP_BLS381_redc(BIG_384_29 x,FP_BLS381 *y)
{
    DBIG_384_29 d;
    BIG_384_29_dzero(d);
    BIG_384_29_dscopy(d,y->g);
    FP_BLS381_mod(x,d);
}

/* fast modular reduction from DBIG to BIG exploiting special form of the modulus */
void FP_BLS381_mod(BIG_384_29 a,DBIG_384_29 d)
{
    int i;

    for (i=0; i<NLEN_384_29; i++)
        d[NLEN_384_29+i]+=muladd_384_29(d[i],MConst_BLS381-1,d[i],&d[NLEN_384_29+i-1]);

    BIG_384_29_sducopy(a,d);
    BIG_384_29_norm(a);
}

#endif

#if MODTYPE_BLS381 == NOT_SPECIAL

/* convert to Montgomery n-residue form */
void FP_BLS381_nres(FP_BLS381 *y,BIG_384_29 x)
{
    DBIG_384_29 d;
    BIG_384_29 r;
    BIG_384_29_rcopy(r,R2modp_BLS381);
    BIG_384_29_mul(d,x,r);
    FP_BLS381_mod(y->g,d);
    y->XES=2;
}

/* convert back to regular form */
void FP_BLS381_redc(BIG_384_29 x,FP_BLS381 *y)
{
    DBIG_384_29 d;
    BIG_384_29_dzero(d);
    BIG_384_29_dscopy(d,y->g);
    FP_BLS381_mod(x,d);
}


/* reduce a DBIG to a BIG using Montgomery's no trial division method */
/* d is expected to be dnormed before entry */
/* SU= 112 */
void FP_BLS381_mod(BIG_384_29 a,DBIG_384_29 d)
{
    BIG_384_29 mdls;
    BIG_384_29_rcopy(mdls,Modulus_BLS381);
    BIG_384_29_monty(a,mdls,MConst_BLS381,d);
}

#endif

/* test x==0 ? */
/* SU= 48 */
int FP_BLS381_iszilch(FP_BLS381 *x)
{
    BIG_384_29 m,t;
    BIG_384_29_rcopy(m,Modulus_BLS381);
    BIG_384_29_copy(t,x->g);
    BIG_384_29_mod(t,m);
    return BIG_384_29_iszilch(t);
}

void FP_BLS381_copy(FP_BLS381 *y,FP_BLS381 *x)
{
    BIG_384_29_copy(y->g,x->g);
    y->XES=x->XES;
}

void FP_BLS381_rcopy(FP_BLS381 *y, const BIG_384_29 c)
{
    BIG_384_29 b;
    BIG_384_29_rcopy(b,c);
    FP_BLS381_nres(y,b);
}

/* Swap a and b if d=1 */
void FP_BLS381_cswap(FP_BLS381 *a,FP_BLS381 *b,int d)
{
    sign32 t,c=d;
    BIG_384_29_cswap(a->g,b->g,d);

    c=~(c-1);
    t=c&((a->XES)^(b->XES));
    a->XES^=t;
    b->XES^=t;

}

/* Move b to a if d=1 */
void FP_BLS381_cmove(FP_BLS381 *a,FP_BLS381 *b,int d)
{
    sign32 c=-d;

    BIG_384_29_cmove(a->g,b->g,d);
    a->XES^=(a->XES^b->XES)&c;
}

void FP_BLS381_zero(FP_BLS381 *x)
{
    BIG_384_29_zero(x->g);
    x->XES=1;
}

int FP_BLS381_equals(FP_BLS381 *x,FP_BLS381 *y)
{
    FP_BLS381 xg,yg;
    FP_BLS381_copy(&xg,x);
    FP_BLS381_copy(&yg,y);
    FP_BLS381_reduce(&xg);
    FP_BLS381_reduce(&yg);
    if (BIG_384_29_comp(xg.g,yg.g)==0) return 1;
    return 0;
}

/* output FP */
/* SU= 48 */
void FP_BLS381_output(FP_BLS381 *r)
{
    BIG_384_29 c;
    FP_BLS381_redc(c,r);
    BIG_384_29_output(c);
}

void FP_BLS381_rawoutput(FP_BLS381 *r)
{
    BIG_384_29_rawoutput(r->g);
}

#ifdef GET_STATS
int tsqr=0,rsqr=0,tmul=0,rmul=0;
int tadd=0,radd=0,tneg=0,rneg=0;
int tdadd=0,rdadd=0,tdneg=0,rdneg=0;
#endif

#ifdef FUSED_MODMUL

/* Insert fastest code here */

#endif

/* r=a*b mod Modulus */
/* product must be less that p.R - and we need to know this in advance! */
/* SU= 88 */
void FP_BLS381_mul(FP_BLS381 *r,FP_BLS381 *a,FP_BLS381 *b)
{
    DBIG_384_29 d;

    if ((sign64)a->XES*b->XES>(sign64)FEXCESS_BLS381)
    {
#ifdef DEBUG_REDUCE
        printf("Product too large - reducing it\n");
#endif
        FP_BLS381_reduce(a);  /* it is sufficient to fully reduce just one of them < p */
    }

#ifdef FUSED_MODMUL
    FP_BLS381_modmul(r->g,a->g,b->g);
#else
    BIG_384_29_mul(d,a->g,b->g);
    FP_BLS381_mod(r->g,d);
#endif
    r->XES=2;
}


/* multiplication by an integer, r=a*c */
/* SU= 136 */
void FP_BLS381_imul(FP_BLS381 *r,FP_BLS381 *a,int c)
{
    int s=0;

    if (c<0)
    {
        c=-c;
        s=1;
    }

#if MODTYPE_BLS381==PSEUDO_MERSENNE || MODTYPE_BLS381==GENERALISED_MERSENNE
    DBIG_384_29 d;
    BIG_384_29_pxmul(d,a->g,c);
    FP_BLS381_mod(r->g,d);
    r->XES=2;

#else
    //Montgomery
    BIG_384_29 k;
    FP_BLS381 f;
    if (a->XES*c<=FEXCESS_BLS381)
    {
        BIG_384_29_pmul(r->g,a->g,c);
        r->XES=a->XES*c;    // careful here - XES jumps!
    }
    else
    {
        // don't want to do this - only a problem for Montgomery modulus and larger constants
        BIG_384_29_zero(k);
        BIG_384_29_inc(k,c);
        BIG_384_29_norm(k);
        FP_BLS381_nres(&f,k);
        FP_BLS381_mul(r,a,&f);
    }
#endif

    if (s)
    {
        FP_BLS381_neg(r,r);
        FP_BLS381_norm(r);
    }
}

/* Set r=a^2 mod m */
/* SU= 88 */
void FP_BLS381_sqr(FP_BLS381 *r,FP_BLS381 *a)
{
    DBIG_384_29 d;

    if ((sign64)a->XES*a->XES>(sign64)FEXCESS_BLS381)
    {
#ifdef DEBUG_REDUCE
        printf("Product too large - reducing it\n");
#endif
        FP_BLS381_reduce(a);
    }

    BIG_384_29_sqr(d,a->g);
    FP_BLS381_mod(r->g,d);
    r->XES=2;
}

/* SU= 16 */
/* Set r=a+b */
void FP_BLS381_add(FP_BLS381 *r,FP_BLS381 *a,FP_BLS381 *b)
{
    BIG_384_29_add(r->g,a->g,b->g);
    r->XES=a->XES+b->XES;
    if (r->XES>FEXCESS_BLS381)
    {
#ifdef DEBUG_REDUCE
        printf("Sum too large - reducing it \n");
#endif
        FP_BLS381_reduce(r);
    }
}

/* Set r=a-b mod m */
/* SU= 56 */
void FP_BLS381_sub(FP_BLS381 *r,FP_BLS381 *a,FP_BLS381 *b)
{
    FP_BLS381 n;
    FP_BLS381_neg(&n,b);
    FP_BLS381_add(r,a,&n);
}

// https://graphics.stanford.edu/~seander/bithacks.html
// constant time log to base 2 (or number of bits in)

static int logb2(unsign32 v)
{
    int r;
    v |= v >> 1;
    v |= v >> 2;
    v |= v >> 4;
    v |= v >> 8;
    v |= v >> 16;

    v = v - ((v >> 1) & 0x55555555);
    v = (v & 0x33333333) + ((v >> 2) & 0x33333333);
    r = (((v + (v >> 4)) & 0xF0F0F0F) * 0x1010101) >> 24;
    return r;
}

// find appoximation to quotient of a/m
// Out by at most 2.
// Note that MAXXES is bounded to be 2-bits less than half a word
static int quo(BIG_384_29 n,BIG_384_29 m)
{
    int sh;
    chunk num,den;
    int hb=CHUNK/2;
    if (TBITS_BLS381<hb)
    {
        sh=hb-TBITS_BLS381;
        num=(n[NLEN_384_29-1]<<sh)|(n[NLEN_384_29-2]>>(BASEBITS_384_29-sh));
        den=(m[NLEN_384_29-1]<<sh)|(m[NLEN_384_29-2]>>(BASEBITS_384_29-sh));
    }
    else
    {
        num=n[NLEN_384_29-1];
        den=m[NLEN_384_29-1];
    }
    return (int)(num/(den+1));
}

/* SU= 48 */
/* Fully reduce a mod Modulus */
void FP_BLS381_reduce(FP_BLS381 *a)
{
    BIG_384_29 m,r;
    int sr,sb,q;
    chunk carry;

    BIG_384_29_rcopy(m,Modulus_BLS381);

    BIG_384_29_norm(a->g);

    if (a->XES>16)
    {
        q=quo(a->g,m);
        carry=BIG_384_29_pmul(r,m,q);
        r[NLEN_384_29-1]+=(carry<<BASEBITS_384_29); // correction - put any carry out back in again
        BIG_384_29_sub(a->g,a->g,r);
        BIG_384_29_norm(a->g);
        sb=2;
    }
    else sb=logb2(a->XES-1);  // sb does not depend on the actual data

    BIG_384_29_fshl(m,sb);

    while (sb>0)
    {
// constant time...
        sr=BIG_384_29_ssn(r,a->g,m);  // optimized combined shift, subtract and norm
        BIG_384_29_cmove(a->g,r,1-sr);
        sb--;
    }

    //BIG_384_29_mod(a->g,m);
    a->XES=1;
}

void FP_BLS381_norm(FP_BLS381 *x)
{
    BIG_384_29_norm(x->g);
}

/* Set r=-a mod Modulus */
/* SU= 64 */
void FP_BLS381_neg(FP_BLS381 *r,FP_BLS381 *a)
{
    int sb;
    BIG_384_29 m;

    BIG_384_29_rcopy(m,Modulus_BLS381);

    sb=logb2(a->XES-1);
    BIG_384_29_fshl(m,sb);
    BIG_384_29_sub(r->g,m,a->g);
    r->XES=((sign32)1<<sb)+1;

    if (r->XES>FEXCESS_BLS381)
    {
#ifdef DEBUG_REDUCE
        printf("Negation too large -  reducing it \n");
#endif
        FP_BLS381_reduce(r);
    }

}

/* Set r=a/2. */
/* SU= 56 */
void FP_BLS381_div2(FP_BLS381 *r,FP_BLS381 *a)
{
    BIG_384_29 m;
    BIG_384_29_rcopy(m,Modulus_BLS381);
    FP_BLS381_copy(r,a);

    if (BIG_384_29_parity(a->g)==0)
    {

        BIG_384_29_fshr(r->g,1);
    }
    else
    {
        BIG_384_29_add(r->g,r->g,m);
        BIG_384_29_norm(r->g);
        BIG_384_29_fshr(r->g,1);
    }
}

#if MODTYPE_BLS381 == PSEUDO_MERSENNE || MODTYPE_BLS381==GENERALISED_MERSENNE

// See eprint paper https://eprint.iacr.org/2018/1038
// If p=3 mod 4 r= x^{(p-3)/4}, if p=5 mod 8 r=x^{(p-5)/8}

static void FP_BLS381_fpow(FP_BLS381 *r,FP_BLS381 *x)
{
    int i,j,k,bw,w,c,nw,lo,m,n;
    FP_BLS381 xp[11],t,key;
    const int ac[]= {1,2,3,6,12,15,30,60,120,240,255};
// phase 1
    FP_BLS381_copy(&xp[0],x);	// 1
    FP_BLS381_sqr(&xp[1],x); // 2
    FP_BLS381_mul(&xp[2],&xp[1],x);  //3
    FP_BLS381_sqr(&xp[3],&xp[2]);  // 6
    FP_BLS381_sqr(&xp[4],&xp[3]); // 12
    FP_BLS381_mul(&xp[5],&xp[4],&xp[2]); // 15
    FP_BLS381_sqr(&xp[6],&xp[5]); // 30
    FP_BLS381_sqr(&xp[7],&xp[6]); // 60
    FP_BLS381_sqr(&xp[8],&xp[7]); // 120
    FP_BLS381_sqr(&xp[9],&xp[8]); // 240
    FP_BLS381_mul(&xp[10],&xp[9],&xp[5]); // 255

#if MODTYPE_BLS381==PSEUDO_MERSENNE
    n=MODBITS_BLS381;
#endif
#if MODTYPE_BLS381==GENERALISED_MERSENNE  // Goldilocks ONLY
    n=MODBITS_BLS381/2;
#endif

    if (MOD8_BLS381==5)
    {
        n-=3;
        c=(MConst_BLS381+5)/8;
    }
    else
    {
        n-=2;
        c=(MConst_BLS381+3)/4;
    }

    bw=0;
    w=1;
    while (w<c)
    {
        w*=2;
        bw+=1;
    }
    k=w-c;

    if (k!=0)
    {
        i=10;
        while (ac[i]>k) i--;
        FP_BLS381_copy(&key,&xp[i]);
        k-=ac[i];
    }
    while (k!=0)
    {
        i--;
        if (ac[i]>k) continue;
        FP_BLS381_mul(&key,&key,&xp[i]);
        k-=ac[i];
    }

// phase 2
    FP_BLS381_copy(&xp[1],&xp[2]);
    FP_BLS381_copy(&xp[2],&xp[5]);
    FP_BLS381_copy(&xp[3],&xp[10]);

    j=3;
    m=8;
    nw=n-bw;
    while (2*m<nw)
    {
        FP_BLS381_copy(&t,&xp[j++]);
        for (i=0; i<m; i++)
            FP_BLS381_sqr(&t,&t);
        FP_BLS381_mul(&xp[j],&xp[j-1],&t);
        m*=2;
    }

    lo=nw-m;
    FP_BLS381_copy(r,&xp[j]);

    while (lo!=0)
    {
        m/=2;
        j--;
        if (lo<m) continue;
        lo-=m;
        FP_BLS381_copy(&t,r);
        for (i=0; i<m; i++)
            FP_BLS381_sqr(&t,&t);
        FP_BLS381_mul(r,&t,&xp[j]);
    }
// phase 3

    if (bw!=0)
    {
        for (i=0; i<bw; i++ )
            FP_BLS381_sqr(r,r);
        FP_BLS381_mul(r,r,&key);
    }
#if MODTYPE_BLS381==GENERALISED_MERSENNE  // Goldilocks ONLY
    FP_BLS381_copy(&key,r);
    FP_BLS381_sqr(&t,&key);
    FP_BLS381_mul(r,&t,x);
    for (i=0; i<n+1; i++)
        FP_BLS381_sqr(r,r);
    FP_BLS381_mul(r,r,&key);
#endif
}

void FP_BLS381_inv(FP_BLS381 *r,FP_BLS381 *x)
{
    FP_BLS381 y,t;
    FP_BLS381_fpow(&y,x);
    if (MOD8_BLS381==5)
    {
        // r=x^3.y^8
        FP_BLS381_sqr(&t,x);
        FP_BLS381_mul(&t,&t,x);
        FP_BLS381_sqr(&y,&y);
        FP_BLS381_sqr(&y,&y);
        FP_BLS381_sqr(&y,&y);
        FP_BLS381_mul(r,&t,&y);
    }
    else
    {
        FP_BLS381_sqr(&y,&y);
        FP_BLS381_sqr(&y,&y);
        FP_BLS381_mul(r,&y,x);
    }
}

#else

void FP_BLS381_pow(FP_BLS381 *r,FP_BLS381 *a,BIG_384_29 b)
{
    sign8 w[1+(NLEN_384_29*BASEBITS_384_29+3)/4];
    FP_BLS381 tb[16];
    BIG_384_29 t;
    int i,nb;

    FP_BLS381_norm(a);
    BIG_384_29_norm(b);
    BIG_384_29_copy(t,b);
    nb=1+(BIG_384_29_nbits(t)+3)/4;
    /* convert exponent to 4-bit window */
    for (i=0; i<nb; i++)
    {
        w[i]=BIG_384_29_lastbits(t,4);
        BIG_384_29_dec(t,w[i]);
        BIG_384_29_norm(t);
        BIG_384_29_fshr(t,4);
    }

    FP_BLS381_one(&tb[0]);
    FP_BLS381_copy(&tb[1],a);
    for (i=2; i<16; i++)
        FP_BLS381_mul(&tb[i],&tb[i-1],a);

    FP_BLS381_copy(r,&tb[w[nb-1]]);
    for (i=nb-2; i>=0; i--)
    {
        FP_BLS381_sqr(r,r);
        FP_BLS381_sqr(r,r);
        FP_BLS381_sqr(r,r);
        FP_BLS381_sqr(r,r);
        FP_BLS381_mul(r,r,&tb[w[i]]);
    }
    FP_BLS381_reduce(r);
}

/* set w=1/x */
void FP_BLS381_inv(FP_BLS381 *w,FP_BLS381 *x)
{

    BIG_384_29 m2;
    BIG_384_29_rcopy(m2,Modulus_BLS381);
    BIG_384_29_dec(m2,2);
    BIG_384_29_norm(m2);
    FP_BLS381_pow(w,x,m2);
}
#endif

/* SU=8 */
/* set n=1 */
void FP_BLS381_one(FP_BLS381 *n)
{
    BIG_384_29 b;
    BIG_384_29_one(b);
    FP_BLS381_nres(n,b);
}

/* is r a QR? */
int FP_BLS381_qr(FP_BLS381 *r)
{
    int j;
    BIG_384_29 m;
    BIG_384_29 b;
    BIG_384_29_rcopy(m,Modulus_BLS381);
    FP_BLS381_redc(b,r);
    j=BIG_384_29_jacobi(b,m);
    FP_BLS381_nres(r,b);
    if (j==1) return 1;
    return 0;

}

/* Set a=sqrt(b) mod Modulus */
/* SU= 160 */
void FP_BLS381_sqrt(FP_BLS381 *r,FP_BLS381 *a)
{
    FP_BLS381 v,i;
    BIG_384_29 b;
    BIG_384_29 m;
    BIG_384_29_rcopy(m,Modulus_BLS381);
    BIG_384_29_mod(a->g,m);
    BIG_384_29_copy(b,m);
    if (MOD8_BLS381==5)
    {
        FP_BLS381_copy(&i,a); // i=x
        BIG_384_29_fshl(i.g,1); // i=2x
#if MODTYPE_BLS381 == PSEUDO_MERSENNE   || MODTYPE_BLS381==GENERALISED_MERSENNE
        FP_BLS381_fpow(&v,&i);
#else
        BIG_384_29_dec(b,5);
        BIG_384_29_norm(b);
        BIG_384_29_fshr(b,3); // (p-5)/8
        FP_BLS381_pow(&v,&i,b); // v=(2x)^(p-5)/8
#endif
        FP_BLS381_mul(&i,&i,&v); // i=(2x)^(p+3)/8
        FP_BLS381_mul(&i,&i,&v); // i=(2x)^(p-1)/4
        BIG_384_29_dec(i.g,1);  // i=(2x)^(p-1)/4 - 1
        FP_BLS381_mul(r,a,&v);
        FP_BLS381_mul(r,r,&i);
        FP_BLS381_reduce(r);
    }
    if (MOD8_BLS381==3 || MOD8_BLS381==7)
    {
#if MODTYPE_BLS381 == PSEUDO_MERSENNE   || MODTYPE_BLS381==GENERALISED_MERSENNE
        FP_BLS381_fpow(r,a);
        FP_BLS381_mul(r,r,a);
#else
        BIG_384_29_inc(b,1);
        BIG_384_29_norm(b);
        BIG_384_29_fshr(b,2); /* (p+1)/4 */
        FP_BLS381_pow(r,a,b);
#endif
    }
}
