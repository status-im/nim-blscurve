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

/* AMCL Fp^2 functions */
/* SU=m, m is Stack Usage (no lazy )*/

/* FP2 elements are of the form a+ib, where i is sqrt(-1) */

#include "fp2_BLS381.h"

/* test x==0 ? */
/* SU= 8 */
int FP2_BLS381_iszilch(FP2_BLS381 *x)
{
    if (FP_BLS381_iszilch(&(x->a)) && FP_BLS381_iszilch(&(x->b))) return 1;
    return 0;
}

/* Move b to a if d=1 */
void FP2_BLS381_cmove(FP2_BLS381 *f,FP2_BLS381 *g,int d)
{
    FP_BLS381_cmove(&(f->a),&(g->a),d);
    FP_BLS381_cmove(&(f->b),&(g->b),d);
}

/* test x==1 ? */
/* SU= 48 */
int FP2_BLS381_isunity(FP2_BLS381 *x)
{
    FP_BLS381 one;
    FP_BLS381_one(&one);
    if (FP_BLS381_equals(&(x->a),&one) && FP_BLS381_iszilch(&(x->b))) return 1;
    return 0;
}

/* SU= 8 */
/* Fully reduce a and b mod Modulus */
void FP2_BLS381_reduce(FP2_BLS381 *w)
{
    FP_BLS381_reduce(&(w->a));
    FP_BLS381_reduce(&(w->b));
}

/* return 1 if x==y, else 0 */
/* SU= 16 */
int FP2_BLS381_equals(FP2_BLS381 *x,FP2_BLS381 *y)
{
    if (FP_BLS381_equals(&(x->a),&(y->a)) && FP_BLS381_equals(&(x->b),&(y->b)))
        return 1;
    return 0;
}

/* Create FP2 from two FPs */
/* SU= 16 */
void FP2_BLS381_from_FPs(FP2_BLS381 *w,FP_BLS381 *x,FP_BLS381 *y)
{
    FP_BLS381_copy(&(w->a),x);
    FP_BLS381_copy(&(w->b),y);
}

/* Create FP2 from two BIGS */
/* SU= 16 */
void FP2_BLS381_from_BIGs(FP2_BLS381 *w,BIG_384_29 x,BIG_384_29 y)
{
    FP_BLS381_nres(&(w->a),x);
    FP_BLS381_nres(&(w->b),y);
}

/* Create FP2 from FP */
/* SU= 8 */
void FP2_BLS381_from_FP(FP2_BLS381 *w,FP_BLS381 *x)
{
    FP_BLS381_copy(&(w->a),x);
    FP_BLS381_zero(&(w->b));
}

/* Create FP2 from BIG */
/* SU= 8 */
void FP2_BLS381_from_BIG(FP2_BLS381 *w,BIG_384_29 x)
{
    FP_BLS381_nres(&(w->a),x);
    FP_BLS381_zero(&(w->b));
}

/* FP2 copy w=x */
/* SU= 16 */
void FP2_BLS381_copy(FP2_BLS381 *w,FP2_BLS381 *x)
{
    if (w==x) return;
    FP_BLS381_copy(&(w->a),&(x->a));
    FP_BLS381_copy(&(w->b),&(x->b));
}

/* FP2 set w=0 */
/* SU= 8 */
void FP2_BLS381_zero(FP2_BLS381 *w)
{
    FP_BLS381_zero(&(w->a));
    FP_BLS381_zero(&(w->b));
}

/* FP2 set w=1 */
/* SU= 48 */
void FP2_BLS381_one(FP2_BLS381 *w)
{
    FP_BLS381 one;
    FP_BLS381_one(&one);
    FP2_BLS381_from_FP(w,&one);
}

/* Set w=-x */
/* SU= 88 */
void FP2_BLS381_neg(FP2_BLS381 *w,FP2_BLS381 *x)
{
    /* Just one neg! */
    FP_BLS381 m,t;
    FP_BLS381_add(&m,&(x->a),&(x->b));
    FP_BLS381_neg(&m,&m);
    FP_BLS381_add(&t,&m,&(x->b));
    FP_BLS381_add(&(w->b),&m,&(x->a));
    FP_BLS381_copy(&(w->a),&t);

}

/* Set w=conj(x) */
/* SU= 16 */
void FP2_BLS381_conj(FP2_BLS381 *w,FP2_BLS381 *x)
{
    FP_BLS381_copy(&(w->a),&(x->a));
    FP_BLS381_neg(&(w->b),&(x->b));
    FP_BLS381_norm(&(w->b));
}

/* Set w=x+y */
/* SU= 16 */
void FP2_BLS381_add(FP2_BLS381 *w,FP2_BLS381 *x,FP2_BLS381 *y)
{
    FP_BLS381_add(&(w->a),&(x->a),&(y->a));
    FP_BLS381_add(&(w->b),&(x->b),&(y->b));
}

/* Set w=x-y */
/* Input y MUST be normed */
void FP2_BLS381_sub(FP2_BLS381 *w,FP2_BLS381 *x,FP2_BLS381 *y)
{
    FP2_BLS381 m;
    FP2_BLS381_neg(&m,y);
    FP2_BLS381_add(w,x,&m);
}

/* Set w=s*x, where s is FP */
/* SU= 16 */
void FP2_BLS381_pmul(FP2_BLS381 *w,FP2_BLS381 *x,FP_BLS381 *s)
{
    FP_BLS381_mul(&(w->a),&(x->a),s);
    FP_BLS381_mul(&(w->b),&(x->b),s);
}

/* SU= 16 */
/* Set w=s*x, where s is int */
void FP2_BLS381_imul(FP2_BLS381 *w,FP2_BLS381 *x,int s)
{
    FP_BLS381_imul(&(w->a),&(x->a),s);
    FP_BLS381_imul(&(w->b),&(x->b),s);
}

/* Set w=x^2 */
/* SU= 128 */
void FP2_BLS381_sqr(FP2_BLS381 *w,FP2_BLS381 *x)
{
    FP_BLS381 w1,w3,mb;

    FP_BLS381_add(&w1,&(x->a),&(x->b));
    FP_BLS381_neg(&mb,&(x->b));

    FP_BLS381_add(&w3,&(x->a),&(x->a));
    FP_BLS381_norm(&w3);
    FP_BLS381_mul(&(w->b),&w3,&(x->b));

    FP_BLS381_add(&(w->a),&(x->a),&mb);

    FP_BLS381_norm(&w1);
    FP_BLS381_norm(&(w->a));

    FP_BLS381_mul(&(w->a),&w1,&(w->a));     /* w->a#2 w->a=1 w1&w2=6 w1*w2=2 */
}

/* Set w=x*y */
/* Inputs MUST be normed  */
/* Now uses Lazy reduction */
void FP2_BLS381_mul(FP2_BLS381 *w,FP2_BLS381 *x,FP2_BLS381 *y)
{
    DBIG_384_29 A,B,E,F,pR;
    BIG_384_29 C,D,p;

    BIG_384_29_rcopy(p,Modulus_BLS381);
    BIG_384_29_dsucopy(pR,p);

// reduce excesses of a and b as required (so product < pR)

    if ((sign64)(x->a.XES+x->b.XES)*(y->a.XES+y->b.XES)>(sign64)FEXCESS_BLS381)
    {
#ifdef DEBUG_REDUCE
        printf("FP2 Product too large - reducing it\n");
#endif
        if (x->a.XES>1) FP_BLS381_reduce(&(x->a));
        if (x->b.XES>1) FP_BLS381_reduce(&(x->b));
    }

    BIG_384_29_mul(A,x->a.g,y->a.g);
    BIG_384_29_mul(B,x->b.g,y->b.g);

    BIG_384_29_add(C,x->a.g,x->b.g);
    BIG_384_29_norm(C);
    BIG_384_29_add(D,y->a.g,y->b.g);
    BIG_384_29_norm(D);

    BIG_384_29_mul(E,C,D);
    BIG_384_29_dadd(F,A,B);
    BIG_384_29_dsub(B,pR,B); //

    BIG_384_29_dadd(A,A,B);    // A<pR? Not necessarily, but <2pR
    BIG_384_29_dsub(E,E,F);    // E<pR ? Yes

    BIG_384_29_dnorm(A);
    FP_BLS381_mod(w->a.g,A);
    w->a.XES=3;// may drift above 2p...
    BIG_384_29_dnorm(E);
    FP_BLS381_mod(w->b.g,E);
    w->b.XES=2;

}

/* output FP2 in hex format [a,b] */
/* SU= 16 */
void FP2_BLS381_output(FP2_BLS381 *w)
{
    BIG_384_29 bx,by;
    FP2_BLS381_reduce(w);
    FP_BLS381_redc(bx,&(w->a));
    FP_BLS381_redc(by,&(w->b));
    printf("[");
    BIG_384_29_output(bx);
    printf(",");
    BIG_384_29_output(by);
    printf("]");
    FP_BLS381_nres(&(w->a),bx);
    FP_BLS381_nres(&(w->b),by);
}

/* SU= 8 */
void FP2_BLS381_rawoutput(FP2_BLS381 *w)
{
    printf("[");
    BIG_384_29_rawoutput(w->a.g);
    printf(",");
    BIG_384_29_rawoutput(w->b.g);
    printf("]");
}


/* Set w=1/x */
/* SU= 128 */
void FP2_BLS381_inv(FP2_BLS381 *w,FP2_BLS381 *x)
{
    FP_BLS381 w1,w2;

    FP2_BLS381_norm(x);
    FP_BLS381_sqr(&w1,&(x->a));
    FP_BLS381_sqr(&w2,&(x->b));
    FP_BLS381_add(&w1,&w1,&w2);

    FP_BLS381_inv(&w1,&w1);

    FP_BLS381_mul(&(w->a),&(x->a),&w1);
    FP_BLS381_neg(&w1,&w1);
    FP_BLS381_norm(&w1);
    FP_BLS381_mul(&(w->b),&(x->b),&w1);
}


/* Set w=x/2 */
/* SU= 16 */
void FP2_BLS381_div2(FP2_BLS381 *w,FP2_BLS381 *x)
{
    FP_BLS381_div2(&(w->a),&(x->a));
    FP_BLS381_div2(&(w->b),&(x->b));
}

/* Set w*=(1+sqrt(-1)) */
/* where X^2-(1+sqrt(-1)) is irreducible for FP4, assumes p=3 mod 8 */

/* Input MUST be normed */
void FP2_BLS381_mul_ip(FP2_BLS381 *w)
{
    FP_BLS381 z;
    FP2_BLS381 t;
    FP2_BLS381_copy(&t,w);

    FP_BLS381_copy(&z,&(w->a));
    FP_BLS381_neg(&(w->a),&(w->b));
    FP_BLS381_copy(&(w->b),&z);

    FP2_BLS381_add(w,&t,w);
//    Output NOT normed, so use with care
}


void FP2_BLS381_div_ip2(FP2_BLS381 *w)
{
    FP2_BLS381 t;
    FP2_BLS381_norm(w);
    FP_BLS381_add(&(t.a),&(w->a),&(w->b));
    FP_BLS381_sub(&(t.b),&(w->b),&(w->a));
    FP2_BLS381_norm(&t);
    FP2_BLS381_copy(w,&t);
}

/* Set w/=(1+sqrt(-1)) */
/* SU= 88 */
void FP2_BLS381_div_ip(FP2_BLS381 *w)
{
    FP2_BLS381 t;
    FP2_BLS381_norm(w);
    FP_BLS381_add(&t.a,&(w->a),&(w->b));
    FP_BLS381_sub(&t.b,&(w->b),&(w->a));
    FP2_BLS381_norm(&t);
    FP2_BLS381_div2(w,&t);
}

/* SU= 8 */
/* normalise a and b components of w */
void FP2_BLS381_norm(FP2_BLS381 *w)
{
    FP_BLS381_norm(&(w->a));
    FP_BLS381_norm(&(w->b));
}

/* Set w=a^b mod m */
/* SU= 208 */
void FP2_BLS381_pow(FP2_BLS381 *r,FP2_BLS381* a,BIG_384_29 b)
{
    FP2_BLS381 w;
    FP_BLS381 one;
    BIG_384_29 z,zilch;
    int bt;

    BIG_384_29_norm(b);
    BIG_384_29_copy(z,b);
    FP2_BLS381_copy(&w,a);
    FP_BLS381_one(&one);
    BIG_384_29_zero(zilch);
    FP2_BLS381_from_FP(r,&one);
    while(1)
    {
        bt=BIG_384_29_parity(z);
        BIG_384_29_shr(z,1);
        if (bt) FP2_BLS381_mul(r,r,&w);
        if (BIG_384_29_comp(z,zilch)==0) break;
        FP2_BLS381_sqr(&w,&w);
    }
    FP2_BLS381_reduce(r);
}

/* sqrt(a+ib) = sqrt(a+sqrt(a*a-n*b*b)/2)+ib/(2*sqrt(a+sqrt(a*a-n*b*b)/2)) */
/* returns true if u is QR */

int FP2_BLS381_sqrt(FP2_BLS381 *w,FP2_BLS381 *u)
{
    FP_BLS381 w1,w2;
    FP2_BLS381_copy(w,u);
    if (FP2_BLS381_iszilch(w)) return 1;

    FP_BLS381_sqr(&w1,&(w->b));
    FP_BLS381_sqr(&w2,&(w->a));
    FP_BLS381_add(&w1,&w1,&w2);
    if (!FP_BLS381_qr(&w1))
    {
        FP2_BLS381_zero(w);
        return 0;
    }
    FP_BLS381_sqrt(&w1,&w1);
    FP_BLS381_add(&w2,&(w->a),&w1);
    FP_BLS381_norm(&w2);
    FP_BLS381_div2(&w2,&w2);
    if (!FP_BLS381_qr(&w2))
    {
        FP_BLS381_sub(&w2,&(w->a),&w1);
        FP_BLS381_norm(&w2);
        FP_BLS381_div2(&w2,&w2);
        if (!FP_BLS381_qr(&w2))
        {
            FP2_BLS381_zero(w);
            return 0;
        }
    }
    FP_BLS381_sqrt(&w2,&w2);
    FP_BLS381_copy(&(w->a),&w2);
    FP_BLS381_add(&w2,&w2,&w2);

    FP_BLS381_inv(&w2,&w2);

    FP_BLS381_mul(&(w->b),&(w->b),&w2);
    return 1;
}

/* New stuff for ECp4 support */

/* Input MUST be normed */
void FP2_BLS381_times_i(FP2_BLS381 *w)
{
    FP_BLS381 z;
    FP_BLS381_copy(&z,&(w->a));
    FP_BLS381_neg(&(w->a),&(w->b));
    FP_BLS381_copy(&(w->b),&z);

//    Output NOT normed, so use with care
}

