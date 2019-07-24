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

/* AMCL Elliptic Curve Functions */
/* SU=m, SU is Stack Usage (Weierstrass Curves) */

//#define HAS_MAIN

#include "ecp_BLS381.h"

/* test for P=O point-at-infinity */
int ECP_BLS381_isinf(ECP_BLS381 *P)
{

#if CURVETYPE_BLS381==EDWARDS
    return (FP_BLS381_iszilch(&(P->x)) && FP_BLS381_equals(&(P->y),&(P->z)));
#endif
#if CURVETYPE_BLS381==WEIERSTRASS
    return (FP_BLS381_iszilch(&(P->x)) && FP_BLS381_iszilch(&(P->z)));
#endif
#if CURVETYPE_BLS381==MONTGOMERY
    return FP_BLS381_iszilch(&(P->z));
#endif

}

/* Conditional swap of P and Q dependant on d */
static void ECP_BLS381_cswap(ECP_BLS381 *P,ECP_BLS381 *Q,int d)
{
    FP_BLS381_cswap(&(P->x),&(Q->x),d);
#if CURVETYPE_BLS381!=MONTGOMERY
    FP_BLS381_cswap(&(P->y),&(Q->y),d);
#endif
    FP_BLS381_cswap(&(P->z),&(Q->z),d);
}

#if CURVETYPE_BLS381!=MONTGOMERY
/* Conditional move Q to P dependant on d */
static void ECP_BLS381_cmove(ECP_BLS381 *P,ECP_BLS381 *Q,int d)
{
    FP_BLS381_cmove(&(P->x),&(Q->x),d);
#if CURVETYPE_BLS381!=MONTGOMERY
    FP_BLS381_cmove(&(P->y),&(Q->y),d);
#endif
    FP_BLS381_cmove(&(P->z),&(Q->z),d);
}

/* return 1 if b==c, no branching */
static int teq(sign32 b,sign32 c)
{
    sign32 x=b^c;
    x-=1;  // if x=0, x now -1
    return (int)((x>>31)&1);
}
#endif // CURVETYPE_BLS381!=MONTGOMERY

#if CURVETYPE_BLS381!=MONTGOMERY
/* Constant time select from pre-computed table */
static void ECP_BLS381_select(ECP_BLS381 *P,ECP_BLS381 W[],sign32 b)
{
    ECP_BLS381 MP;
    sign32 m=b>>31;
    sign32 babs=(b^m)-m;

    babs=(babs-1)/2;

    ECP_BLS381_cmove(P,&W[0],teq(babs,0));  // conditional move
    ECP_BLS381_cmove(P,&W[1],teq(babs,1));
    ECP_BLS381_cmove(P,&W[2],teq(babs,2));
    ECP_BLS381_cmove(P,&W[3],teq(babs,3));
    ECP_BLS381_cmove(P,&W[4],teq(babs,4));
    ECP_BLS381_cmove(P,&W[5],teq(babs,5));
    ECP_BLS381_cmove(P,&W[6],teq(babs,6));
    ECP_BLS381_cmove(P,&W[7],teq(babs,7));

    ECP_BLS381_copy(&MP,P);
    ECP_BLS381_neg(&MP);  // minus P
    ECP_BLS381_cmove(P,&MP,(int)(m&1));
}
#endif

/* Test P == Q */
/* SU=168 */
int ECP_BLS381_equals(ECP_BLS381 *P,ECP_BLS381 *Q)
{
    FP_BLS381 a,b;

    FP_BLS381_mul(&a,&(P->x),&(Q->z));
    FP_BLS381_mul(&b,&(Q->x),&(P->z));
    if (!FP_BLS381_equals(&a,&b)) return 0;

#if CURVETYPE_BLS381!=MONTGOMERY
    FP_BLS381_mul(&a,&(P->y),&(Q->z));
    FP_BLS381_mul(&b,&(Q->y),&(P->z));
    if (!FP_BLS381_equals(&a,&b)) return 0;
#endif

    return 1;

}

/* Set P=Q */
/* SU=16 */
void ECP_BLS381_copy(ECP_BLS381 *P,ECP_BLS381 *Q)
{
    FP_BLS381_copy(&(P->x),&(Q->x));
#if CURVETYPE_BLS381!=MONTGOMERY
    FP_BLS381_copy(&(P->y),&(Q->y));
#endif
    FP_BLS381_copy(&(P->z),&(Q->z));
}

/* Set P=-Q */
#if CURVETYPE_BLS381!=MONTGOMERY
/* SU=8 */
void ECP_BLS381_neg(ECP_BLS381 *P)
{
#if CURVETYPE_BLS381==WEIERSTRASS
    FP_BLS381_neg(&(P->y),&(P->y));
    FP_BLS381_norm(&(P->y));
#else
    FP_BLS381_neg(&(P->x),&(P->x));
    FP_BLS381_norm(&(P->x));
#endif

}
#endif

/* Set P=O */
void ECP_BLS381_inf(ECP_BLS381 *P)
{
    FP_BLS381_zero(&(P->x));
#if CURVETYPE_BLS381!=MONTGOMERY
    FP_BLS381_one(&(P->y));
#endif
#if CURVETYPE_BLS381!=EDWARDS
    FP_BLS381_zero(&(P->z));
#else
    FP_BLS381_one(&(P->z));
#endif
}

/* Calculate right Hand Side of curve equation y^2=RHS */
/* SU=56 */
void ECP_BLS381_rhs(FP_BLS381 *v,FP_BLS381 *x)
{
#if CURVETYPE_BLS381==WEIERSTRASS
    /* x^3+Ax+B */
    FP_BLS381 t;
    FP_BLS381_sqr(&t,x);
    FP_BLS381_mul(&t,&t,x);

    if (CURVE_A_BLS381==-3)
    {
        FP_BLS381_neg(v,x);
        FP_BLS381_norm(v);
        FP_BLS381_imul(v,v,-CURVE_A_BLS381);
        FP_BLS381_norm(v);
        FP_BLS381_add(v,&t,v);
    }
    else FP_BLS381_copy(v,&t);

    FP_BLS381_rcopy(&t,CURVE_B_BLS381);

    FP_BLS381_add(v,&t,v);
    FP_BLS381_reduce(v);
#endif

#if CURVETYPE_BLS381==EDWARDS
    /* (Ax^2-1)/(Bx^2-1) */
    FP_BLS381 t,one;
    FP_BLS381_sqr(v,x);
    FP_BLS381_one(&one);
    FP_BLS381_rcopy(&t,CURVE_B_BLS381);

    FP_BLS381_mul(&t,v,&t);
    FP_BLS381_sub(&t,&t,&one);
    FP_BLS381_norm(&t);
    if (CURVE_A_BLS381==1) FP_BLS381_sub(v,v,&one);

    if (CURVE_A_BLS381==-1)
    {
        FP_BLS381_add(v,v,&one);
        FP_BLS381_norm(v);
        FP_BLS381_neg(v,v);
    }
    FP_BLS381_norm(v);
    FP_BLS381_inv(&t,&t);
    FP_BLS381_mul(v,v,&t);
    FP_BLS381_reduce(v);
#endif

#if CURVETYPE_BLS381==MONTGOMERY
    /* x^3+Ax^2+x */
    FP_BLS381 x2,x3;
    FP_BLS381_sqr(&x2,x);
    FP_BLS381_mul(&x3,&x2,x);
    FP_BLS381_copy(v,x);
    FP_BLS381_imul(&x2,&x2,CURVE_A_BLS381);
    FP_BLS381_add(v,v,&x2);
    FP_BLS381_add(v,v,&x3);
    FP_BLS381_reduce(v);
#endif
}

#if CURVETYPE_BLS381==MONTGOMERY

/* Set P=(x,{y}) */

int ECP_BLS381_set(ECP_BLS381 *P,BIG_384_29 x)
{
    BIG_384_29 m,b;
    FP_BLS381 rhs;
    BIG_384_29_rcopy(m,Modulus_BLS381);

    FP_BLS381_nres(&rhs,x);

    ECP_BLS381_rhs(&rhs,&rhs);
    FP_BLS381_redc(b,&rhs);

    if (BIG_384_29_jacobi(b,m)!=1)
    {
        ECP_BLS381_inf(P);
        return 0;
    }

    FP_BLS381_nres(&(P->x),x);
    FP_BLS381_one(&(P->z));
    return 1;
}

/* Extract x coordinate as BIG */
int ECP_BLS381_get(BIG_384_29 x,ECP_BLS381 *P)
{
    ECP_BLS381 W;
    ECP_BLS381_copy(&W,P);
    ECP_BLS381_affine(&W);
    if (ECP_BLS381_isinf(&W)) return -1;
    FP_BLS381_redc(x,&(W.x));
    return 0;
}


#else
/* Extract (x,y) and return sign of y. If x and y are the same return only x */
/* SU=16 */
int ECP_BLS381_get(BIG_384_29 x,BIG_384_29 y,ECP_BLS381 *P)
{
    ECP_BLS381 W;
    int s;
    ECP_BLS381_copy(&W,P);
    ECP_BLS381_affine(&W);

    if (ECP_BLS381_isinf(&W)) return -1;

    FP_BLS381_redc(y,&(W.y));
    s=BIG_384_29_parity(y);

    FP_BLS381_redc(x,&(W.x));

    return s;
}

/* Set P=(x,{y}) */
/* SU=96 */
int ECP_BLS381_set(ECP_BLS381 *P,BIG_384_29 x,BIG_384_29 y)
{
    FP_BLS381 rhs,y2;

    FP_BLS381_nres(&y2,y);
    FP_BLS381_sqr(&y2,&y2);
    FP_BLS381_reduce(&y2);

    FP_BLS381_nres(&rhs,x);
    ECP_BLS381_rhs(&rhs,&rhs);

    if (!FP_BLS381_equals(&y2,&rhs))
    {
        ECP_BLS381_inf(P);
        return 0;
    }

    FP_BLS381_nres(&(P->x),x);
    FP_BLS381_nres(&(P->y),y);
    FP_BLS381_one(&(P->z));
    return 1;
}

/* Set P=(x,y), where y is calculated from x with sign s */
/* SU=136 */
int ECP_BLS381_setx(ECP_BLS381 *P,BIG_384_29 x,int s)
{
    FP_BLS381 rhs;
    BIG_384_29 t,m;
    BIG_384_29_rcopy(m,Modulus_BLS381);

    FP_BLS381_nres(&rhs,x);

    ECP_BLS381_rhs(&rhs,&rhs);

    FP_BLS381_redc(t,&rhs);
    if (BIG_384_29_jacobi(t,m)!=1)
    {
        ECP_BLS381_inf(P);
        return 0;
    }

    FP_BLS381_nres(&(P->x),x);
    FP_BLS381_sqrt(&(P->y),&rhs);

    FP_BLS381_redc(t,&(P->y));

    if (BIG_384_29_parity(t)!=s)
        FP_BLS381_neg(&(P->y),&(P->y));
    FP_BLS381_reduce(&(P->y));
    FP_BLS381_one(&(P->z));
    return 1;
}

#endif

void ECP_BLS381_cfp(ECP_BLS381 *P)
{
    /* multiply point by curves cofactor */
    BIG_384_29 c;
    int cf=CURVE_Cof_I_BLS381;
    if (cf==1) return;
    if (cf==4)
    {
        ECP_BLS381_dbl(P);
        ECP_BLS381_dbl(P);
        return;
    }
    if (cf==8)
    {
        ECP_BLS381_dbl(P);
        ECP_BLS381_dbl(P);
        ECP_BLS381_dbl(P);
        return;
    }
    BIG_384_29_rcopy(c,CURVE_Cof_BLS381);
    ECP_BLS381_mul(P,c);
    return;
}

/* map BIG to point on curve of correct order */
/* The BIG should be the output of some hash function */

void ECP_BLS381_mapit(ECP_BLS381 *P,octet *W)
{
    BIG_384_29 q,x;
    BIG_384_29_fromBytes(x,W->val);
    BIG_384_29_rcopy(q,Modulus_BLS381);
    BIG_384_29_mod(x,q);

    for (;;)
    {
        for (;;)
        {
#if CURVETYPE_BLS381!=MONTGOMERY
            ECP_BLS381_setx(P,x,0);
#else
            ECP_BLS381_set(P,x);
#endif
            BIG_384_29_inc(x,1);
            BIG_384_29_norm(x);
            if (!ECP_BLS381_isinf(P)) break;
        }
        ECP_BLS381_cfp(P);
        if (!ECP_BLS381_isinf(P)) break;
    }
}

/* Convert P to Affine, from (x,y,z) to (x,y) */
/* SU=160 */
void ECP_BLS381_affine(ECP_BLS381 *P)
{
    FP_BLS381 one,iz;
    if (ECP_BLS381_isinf(P)) return;
    FP_BLS381_one(&one);
    if (FP_BLS381_equals(&(P->z),&one)) return;

    FP_BLS381_inv(&iz,&(P->z));
    FP_BLS381_mul(&(P->x),&(P->x),&iz);

#if CURVETYPE_BLS381==EDWARDS || CURVETYPE_BLS381==WEIERSTRASS

    FP_BLS381_mul(&(P->y),&(P->y),&iz);
    FP_BLS381_reduce(&(P->y));

#endif

    FP_BLS381_reduce(&(P->x));
    FP_BLS381_copy(&(P->z),&one);
}

/* SU=120 */
void ECP_BLS381_outputxyz(ECP_BLS381 *P)
{
    BIG_384_29 x,z;
    if (ECP_BLS381_isinf(P))
    {
        printf("Infinity\n");
        return;
    }
    FP_BLS381_reduce(&(P->x));
    FP_BLS381_redc(x,&(P->x));
    FP_BLS381_reduce(&(P->z));
    FP_BLS381_redc(z,&(P->z));

#if CURVETYPE_BLS381!=MONTGOMERY
    BIG_384_29 y;
    FP_BLS381_reduce(&(P->y));
    FP_BLS381_redc(y,&(P->y));
    printf("(");
    BIG_384_29_output(x);
    printf(",");
    BIG_384_29_output(y);
    printf(",");
    BIG_384_29_output(z);
    printf(")\n");

#else
    printf("(");
    BIG_384_29_output(x);
    printf(",");
    BIG_384_29_output(z);
    printf(")\n");
#endif
}

/* SU=16 */
/* Output point P */
void ECP_BLS381_output(ECP_BLS381 *P)
{
    BIG_384_29 x;
    if (ECP_BLS381_isinf(P))
    {
        printf("Infinity\n");
        return;
    }
    ECP_BLS381_affine(P);
#if CURVETYPE_BLS381!=MONTGOMERY
    BIG_384_29 y;
    FP_BLS381_redc(x,&(P->x));
    FP_BLS381_redc(y,&(P->y));
    printf("(");
    BIG_384_29_output(x);
    printf(",");
    BIG_384_29_output(y);
    printf(")\n");
#else
    FP_BLS381_redc(x,&(P->x));
    printf("(");
    BIG_384_29_output(x);
    printf(")\n");
#endif
}

/* SU=16 */
/* Output point P */
void ECP_BLS381_rawoutput(ECP_BLS381 *P)
{
    BIG_384_29 x,z;

#if CURVETYPE_BLS381!=MONTGOMERY
    BIG_384_29 y;
    FP_BLS381_redc(x,&(P->x));
    FP_BLS381_redc(y,&(P->y));
    FP_BLS381_redc(z,&(P->z));
    printf("(");
    BIG_384_29_output(x);
    printf(",");
    BIG_384_29_output(y);
    printf(",");
    BIG_384_29_output(z);
    printf(")\n");
#else
    FP_BLS381_redc(x,&(P->x));
    FP_BLS381_redc(z,&(P->z));
    printf("(");
    BIG_384_29_output(x);
    printf(",");
    BIG_384_29_output(z);
    printf(")\n");
#endif
}

/* SU=88 */
/* Convert P to octet string */
void ECP_BLS381_toOctet(octet *W,ECP_BLS381 *P,bool compress)
{
#if CURVETYPE_BLS381==MONTGOMERY
    BIG_384_29 x;
    ECP_BLS381_get(x,P);
    W->len=MODBYTES_384_29+1;
    W->val[0]=6;
    BIG_384_29_toBytes(&(W->val[1]),x);
#else
    BIG_384_29 x,y;
    ECP_BLS381_get(x,y,P);
    if (compress)
    {
        W->val[0]=0x02;
        if (BIG_384_29_parity(y)==1) W->val[0]=0x03;
        W->len=MODBYTES_384_29+1;
        BIG_384_29_toBytes(&(W->val[1]),x);
    }
    else
    {
        W->val[0]=4;
        W->len=2*MODBYTES_384_29+1;
        BIG_384_29_toBytes(&(W->val[1]),x);
        BIG_384_29_toBytes(&(W->val[MODBYTES_384_29+1]),y);
    }
#endif
}

/* SU=88 */
/* Restore P from octet string */
int ECP_BLS381_fromOctet(ECP_BLS381 *P,octet *W)
{
#if CURVETYPE_BLS381==MONTGOMERY
    BIG_384_29 x;
    BIG_384_29_fromBytes(x,&(W->val[1]));
    if (ECP_BLS381_set(P,x)) return 1;
    return 0;
#else
    BIG_384_29 x,y;
    int typ=W->val[0];
    BIG_384_29_fromBytes(x,&(W->val[1]));
    if (typ==0x04)
    {
        BIG_384_29_fromBytes(y,&(W->val[MODBYTES_384_29+1]));
        if (ECP_BLS381_set(P,x,y)) return 1;
    }
    if (typ==0x02 || typ==0x03)
    {
        if (ECP_BLS381_setx(P,x,typ&1)) return 1;
    }
    return 0;
#endif
}


/* Set P=2P */
/* SU=272 */
void ECP_BLS381_dbl(ECP_BLS381 *P)
{
#if CURVETYPE_BLS381==WEIERSTRASS
    FP_BLS381 t0,t1,t2,t3,x3,y3,z3,b;

    if (CURVE_A_BLS381==0)
    {
        FP_BLS381_sqr(&t0,&(P->y));					//t0.sqr();
        FP_BLS381_mul(&t1,&(P->y),&(P->z));			//t1.mul(z);

        FP_BLS381_sqr(&t2,&(P->z));					//t2.sqr();
        FP_BLS381_add(&(P->z),&t0,&t0);		//z.add(t0);
        FP_BLS381_norm(&(P->z));					//z.norm();
        FP_BLS381_add(&(P->z),&(P->z),&(P->z));	//z.add(z);
        FP_BLS381_add(&(P->z),&(P->z),&(P->z));	//z.add(z);
        FP_BLS381_norm(&(P->z));					//z.norm();

        FP_BLS381_imul(&t2,&t2,3*CURVE_B_I_BLS381);		//t2.imul(3*ROM.CURVE_B_I);
        FP_BLS381_mul(&x3,&t2,&(P->z));			//x3.mul(z);

        FP_BLS381_add(&y3,&t0,&t2);				//y3.add(t2);
        FP_BLS381_norm(&y3);						//y3.norm();
        FP_BLS381_mul(&(P->z),&(P->z),&t1);		//z.mul(t1);

        FP_BLS381_add(&t1,&t2,&t2);				//t1.add(t2);
        FP_BLS381_add(&t2,&t2,&t1);				//t2.add(t1);
        FP_BLS381_sub(&t0,&t0,&t2);				//t0.sub(t2);
        FP_BLS381_norm(&t0);						//t0.norm();
        FP_BLS381_mul(&y3,&y3,&t0);				//y3.mul(t0);
        FP_BLS381_add(&y3,&y3,&x3);				//y3.add(x3);
        FP_BLS381_mul(&t1,&(P->x),&(P->y));			//t1.mul(y);

        FP_BLS381_norm(&t0);					//x.norm();
        FP_BLS381_mul(&(P->x),&t0,&t1);		//x.mul(t1);
        FP_BLS381_add(&(P->x),&(P->x),&(P->x));	//x.add(x);
        FP_BLS381_norm(&(P->x));					//x.norm();
        FP_BLS381_copy(&(P->y),&y3);				//y.copy(y3);
        FP_BLS381_norm(&(P->y));					//y.norm();
    }
    else // its -3
    {

        if (CURVE_B_I_BLS381==0)					//if (ROM.CURVE_B_I==0)
            FP_BLS381_rcopy(&b,CURVE_B_BLS381);		//b.copy(new FP(new BIG(ROM.CURVE_B)));

        FP_BLS381_sqr(&t0,&(P->x));					//t0.sqr();  //1    x^2
        FP_BLS381_sqr(&t1,&(P->y));					//t1.sqr();  //2    y^2
        FP_BLS381_sqr(&t2,&(P->z));					//t2.sqr();  //3

        FP_BLS381_mul(&t3,&(P->x),&(P->y));			//t3.mul(y); //4
        FP_BLS381_add(&t3,&t3,&t3);				//t3.add(t3);
        FP_BLS381_norm(&t3);						//t3.norm();//5

        FP_BLS381_mul(&z3,&(P->z),&(P->x));			//z3.mul(x);   //6
        FP_BLS381_add(&z3,&z3,&z3);				//z3.add(z3);
        FP_BLS381_norm(&z3);						//z3.norm();//7

        if (CURVE_B_I_BLS381==0)						//if (ROM.CURVE_B_I==0)
            FP_BLS381_mul(&y3,&t2,&b);				//y3.mul(b); //8
        else
            FP_BLS381_imul(&y3,&t2,CURVE_B_I_BLS381);	//y3.imul(ROM.CURVE_B_I);

        FP_BLS381_sub(&y3,&y3,&z3);				//y3.sub(z3); //y3.norm(); //9  ***
        FP_BLS381_add(&x3,&y3,&y3);				//x3.add(y3);
        FP_BLS381_norm(&x3);						//x3.norm();//10

        FP_BLS381_add(&y3,&y3,&x3);				//y3.add(x3); //y3.norm();//11
        FP_BLS381_sub(&x3,&t1,&y3);				//x3.sub(y3);
        FP_BLS381_norm(&x3);						//x3.norm();//12
        FP_BLS381_add(&y3,&y3,&t1);				//y3.add(t1);
        FP_BLS381_norm(&y3);						//y3.norm();//13
        FP_BLS381_mul(&y3,&y3,&x3);				//y3.mul(x3); //14
        FP_BLS381_mul(&x3,&x3,&t3);				//x3.mul(t3); //15
        FP_BLS381_add(&t3,&t2,&t2);				//t3.add(t2);  //16
        FP_BLS381_add(&t2,&t2,&t3);				//t2.add(t3); //17

        if (CURVE_B_I_BLS381==0)					//if (ROM.CURVE_B_I==0)
            FP_BLS381_mul(&z3,&z3,&b);				//z3.mul(b); //18
        else
            FP_BLS381_imul(&z3,&z3,CURVE_B_I_BLS381);	//z3.imul(ROM.CURVE_B_I);

        FP_BLS381_sub(&z3,&z3,&t2);				//z3.sub(t2); //z3.norm();//19
        FP_BLS381_sub(&z3,&z3,&t0);				//z3.sub(t0);
        FP_BLS381_norm(&z3);						//z3.norm();//20  ***
        FP_BLS381_add(&t3,&z3,&z3);				//t3.add(z3); //t3.norm();//21

        FP_BLS381_add(&z3,&z3,&t3);				//z3.add(t3);
        FP_BLS381_norm(&z3);						//z3.norm(); //22
        FP_BLS381_add(&t3,&t0,&t0);				//t3.add(t0); //t3.norm(); //23
        FP_BLS381_add(&t0,&t0,&t3);				//t0.add(t3); //t0.norm();//24
        FP_BLS381_sub(&t0,&t0,&t2);				//t0.sub(t2);
        FP_BLS381_norm(&t0);						//t0.norm();//25

        FP_BLS381_mul(&t0,&t0,&z3);				//t0.mul(z3);//26
        FP_BLS381_add(&y3,&y3,&t0);				//y3.add(t0); //y3.norm();//27
        FP_BLS381_mul(&t0,&(P->y),&(P->z));			//t0.mul(z);//28
        FP_BLS381_add(&t0,&t0,&t0);				//t0.add(t0);
        FP_BLS381_norm(&t0);						//t0.norm(); //29
        FP_BLS381_mul(&z3,&z3,&t0);				//z3.mul(t0);//30
        FP_BLS381_sub(&(P->x),&x3,&z3);				//x3.sub(z3); //x3.norm();//31
        FP_BLS381_add(&t0,&t0,&t0);				//t0.add(t0);
        FP_BLS381_norm(&t0);						//t0.norm();//32
        FP_BLS381_add(&t1,&t1,&t1);				//t1.add(t1);
        FP_BLS381_norm(&t1);						//t1.norm();//33
        FP_BLS381_mul(&(P->z),&t0,&t1);				//z3.mul(t1);//34

        FP_BLS381_norm(&(P->x));					//x.norm();
        FP_BLS381_copy(&(P->y),&y3);				//y.copy(y3);
        FP_BLS381_norm(&(P->y));					//y.norm();
        FP_BLS381_norm(&(P->z));					//z.norm();
    }
#endif

#if CURVETYPE_BLS381==EDWARDS
    /* Not using square for multiplication swap, as (1) it needs more adds, and (2) it triggers more reductions */

    FP_BLS381 C,D,H,J;

    FP_BLS381_sqr(&C,&(P->x));							//C.sqr();

    FP_BLS381_mul(&(P->x),&(P->x),&(P->y));		//x.mul(y);
    FP_BLS381_add(&(P->x),&(P->x),&(P->x));		//x.add(x);
    FP_BLS381_norm(&(P->x));						//x.norm();

    FP_BLS381_sqr(&D,&(P->y));							//D.sqr();

    if (CURVE_A_BLS381==-1)				//if (ROM.CURVE_A==-1)
        FP_BLS381_neg(&C,&C);				//	C.neg();

    FP_BLS381_add(&(P->y),&C,&D);		//y.add(D);
    FP_BLS381_norm(&(P->y));				//y.norm();
    FP_BLS381_sqr(&H,&(P->z));				//H.sqr();
    FP_BLS381_add(&H,&H,&H);				//H.add(H);

    FP_BLS381_sub(&J,&(P->y),&H);			//J.sub(H);
    FP_BLS381_norm(&J);					//J.norm();

    FP_BLS381_mul(&(P->x),&(P->x),&J);		//x.mul(J);
    FP_BLS381_sub(&C,&C,&D);				//C.sub(D);
    FP_BLS381_norm(&C);					//C.norm();
    FP_BLS381_mul(&(P->z),&(P->y),&J);		//z.mul(J);
    FP_BLS381_mul(&(P->y),&(P->y),&C);		//y.mul(C);


#endif

#if CURVETYPE_BLS381==MONTGOMERY
    FP_BLS381 A,B,AA,BB,C;

    FP_BLS381_add(&A,&(P->x),&(P->z));			//A.add(z);
    FP_BLS381_norm(&A);					//A.norm();
    FP_BLS381_sqr(&AA,&A);				//AA.sqr();
    FP_BLS381_sub(&B,&(P->x),&(P->z));			//B.sub(z);
    FP_BLS381_norm(&B);					//B.norm();

    FP_BLS381_sqr(&BB,&B);				//BB.sqr();
    FP_BLS381_sub(&C,&AA,&BB);				//C.sub(BB);
    FP_BLS381_norm(&C);					//C.norm();
    FP_BLS381_mul(&(P->x),&AA,&BB);	//x.mul(BB);
    FP_BLS381_imul(&A,&C,(CURVE_A_BLS381+2)/4);	//A.imul((ROM.CURVE_A+2)/4);

    FP_BLS381_add(&BB,&BB,&A);				//BB.add(A);
    FP_BLS381_norm(&BB);					//BB.norm();
    FP_BLS381_mul(&(P->z),&BB,&C);		//z.mul(C);

#endif
}

#if CURVETYPE_BLS381==MONTGOMERY

/* Set P+=Q. W is difference between P and Q and is affine */
void ECP_BLS381_add(ECP_BLS381 *P,ECP_BLS381 *Q,ECP_BLS381 *W)
{
    FP_BLS381 A,B,C,D,DA,CB;

    FP_BLS381_add(&A,&(P->x),&(P->z));	//A.add(z);
    FP_BLS381_sub(&B,&(P->x),&(P->z));	//B.sub(z);

    FP_BLS381_add(&C,&(Q->x),&(Q->z));	//C.add(Q.z);

    FP_BLS381_sub(&D,&(Q->x),&(Q->z));	//D.sub(Q.z);
    FP_BLS381_norm(&A);			//A.norm();

    FP_BLS381_norm(&D);			//D.norm();
    FP_BLS381_mul(&DA,&D,&A);			//DA.mul(A);

    FP_BLS381_norm(&C);			//C.norm();
    FP_BLS381_norm(&B);			//B.norm();
    FP_BLS381_mul(&CB,&C,&B);		//CB.mul(B);

    FP_BLS381_add(&A,&DA,&CB);		//A.add(CB);
    FP_BLS381_norm(&A);			//A.norm();
    FP_BLS381_sqr(&(P->x),&A);			//A.sqr();
    FP_BLS381_sub(&B,&DA,&CB);		//B.sub(CB);
    FP_BLS381_norm(&B);			//B.norm();
    FP_BLS381_sqr(&B,&B);			//B.sqr();

    FP_BLS381_mul(&(P->z),&(W->x),&B);	//z.mul(B);

}

#else

/* Set P+=Q */
/* SU=248 */
void ECP_BLS381_add(ECP_BLS381 *P,ECP_BLS381 *Q)
{
#if CURVETYPE_BLS381==WEIERSTRASS

    int b3;
    FP_BLS381 t0,t1,t2,t3,t4,x3,y3,z3,b;

    if (CURVE_A_BLS381==0)
    {
        b3=3*CURVE_B_I_BLS381;					//int b=3*ROM.CURVE_B_I;
        FP_BLS381_mul(&t0,&(P->x),&(Q->x));		//t0.mul(Q.x);
        FP_BLS381_mul(&t1,&(P->y),&(Q->y));		//t1.mul(Q.y);
        FP_BLS381_mul(&t2,&(P->z),&(Q->z));		//t2.mul(Q.z);
        FP_BLS381_add(&t3,&(P->x),&(P->y));		//t3.add(y);
        FP_BLS381_norm(&t3);					//t3.norm();

        FP_BLS381_add(&t4,&(Q->x),&(Q->y));		//t4.add(Q.y);
        FP_BLS381_norm(&t4);					//t4.norm();
        FP_BLS381_mul(&t3,&t3,&t4);			//t3.mul(t4);
        FP_BLS381_add(&t4,&t0,&t1);			//t4.add(t1);

        FP_BLS381_sub(&t3,&t3,&t4);			//t3.sub(t4);
        FP_BLS381_norm(&t3);					//t3.norm();
        FP_BLS381_add(&t4,&(P->y),&(P->z));		//t4.add(z);
        FP_BLS381_norm(&t4);					//t4.norm();
        FP_BLS381_add(&x3,&(Q->y),&(Q->z));		//x3.add(Q.z);
        FP_BLS381_norm(&x3);					//x3.norm();

        FP_BLS381_mul(&t4,&t4,&x3);			//t4.mul(x3);
        FP_BLS381_add(&x3,&t1,&t2);			//x3.add(t2);

        FP_BLS381_sub(&t4,&t4,&x3);			//t4.sub(x3);
        FP_BLS381_norm(&t4);					//t4.norm();
        FP_BLS381_add(&x3,&(P->x),&(P->z));		//x3.add(z);
        FP_BLS381_norm(&x3);					//x3.norm();
        FP_BLS381_add(&y3,&(Q->x),&(Q->z));		//y3.add(Q.z);
        FP_BLS381_norm(&y3);					//y3.norm();
        FP_BLS381_mul(&x3,&x3,&y3);			//x3.mul(y3);

        FP_BLS381_add(&y3,&t0,&t2);			//y3.add(t2);
        FP_BLS381_sub(&y3,&x3,&y3);			//y3.rsub(x3);
        FP_BLS381_norm(&y3);					//y3.norm();
        FP_BLS381_add(&x3,&t0,&t0);			//x3.add(t0);
        FP_BLS381_add(&t0,&t0,&x3);			//t0.add(x3);
        FP_BLS381_norm(&t0);					//t0.norm();
        FP_BLS381_imul(&t2,&t2,b3);				//t2.imul(b);

        FP_BLS381_add(&z3,&t1,&t2);			//z3.add(t2);
        FP_BLS381_norm(&z3);					//z3.norm();
        FP_BLS381_sub(&t1,&t1,&t2);			//t1.sub(t2);
        FP_BLS381_norm(&t1);					//t1.norm();
        FP_BLS381_imul(&y3,&y3,b3);				//y3.imul(b);

        FP_BLS381_mul(&x3,&y3,&t4);			//x3.mul(t4);
        FP_BLS381_mul(&t2,&t3,&t1);			//t2.mul(t1);
        FP_BLS381_sub(&(P->x),&t2,&x3);			//x3.rsub(t2);
        FP_BLS381_mul(&y3,&y3,&t0);			//y3.mul(t0);
        FP_BLS381_mul(&t1,&t1,&z3);			//t1.mul(z3);
        FP_BLS381_add(&(P->y),&y3,&t1);			//y3.add(t1);
        FP_BLS381_mul(&t0,&t0,&t3);			//t0.mul(t3);
        FP_BLS381_mul(&z3,&z3,&t4);			//z3.mul(t4);
        FP_BLS381_add(&(P->z),&z3,&t0);			//z3.add(t0);

        FP_BLS381_norm(&(P->x));				//x.norm();
        FP_BLS381_norm(&(P->y));				//y.norm();
        FP_BLS381_norm(&(P->z));				//z.norm();
    }
    else
    {

        if (CURVE_B_I_BLS381==0)				//if (ROM.CURVE_B_I==0)
            FP_BLS381_rcopy(&b,CURVE_B_BLS381);	//b.copy(new FP(new BIG(ROM.CURVE_B)));

        FP_BLS381_mul(&t0,&(P->x),&(Q->x));		//t0.mul(Q.x); //1
        FP_BLS381_mul(&t1,&(P->y),&(Q->y));		//t1.mul(Q.y); //2
        FP_BLS381_mul(&t2,&(P->z),&(Q->z));		//t2.mul(Q.z); //3

        FP_BLS381_add(&t3,&(P->x),&(P->y));		//t3.add(y);
        FP_BLS381_norm(&t3);					//t3.norm(); //4
        FP_BLS381_add(&t4,&(Q->x),&(Q->y));		//t4.add(Q.y);
        FP_BLS381_norm(&t4);					//t4.norm();//5
        FP_BLS381_mul(&t3,&t3,&t4);			//t3.mul(t4);//6

        FP_BLS381_add(&t4,&t0,&t1);			//t4.add(t1); //t4.norm(); //7
        FP_BLS381_sub(&t3,&t3,&t4);			//t3.sub(t4);
        FP_BLS381_norm(&t3);					//t3.norm(); //8
        FP_BLS381_add(&t4,&(P->y),&(P->z));		//t4.add(z);
        FP_BLS381_norm(&t4);					//t4.norm();//9
        FP_BLS381_add(&x3,&(Q->y),&(Q->z));		//x3.add(Q.z);
        FP_BLS381_norm(&x3);					//x3.norm();//10
        FP_BLS381_mul(&t4,&t4,&x3);			//t4.mul(x3); //11
        FP_BLS381_add(&x3,&t1,&t2);			//x3.add(t2); //x3.norm();//12

        FP_BLS381_sub(&t4,&t4,&x3);			//t4.sub(x3);
        FP_BLS381_norm(&t4);					//t4.norm();//13
        FP_BLS381_add(&x3,&(P->x),&(P->z));		//x3.add(z);
        FP_BLS381_norm(&x3);					//x3.norm(); //14
        FP_BLS381_add(&y3,&(Q->x),&(Q->z));		//y3.add(Q.z);
        FP_BLS381_norm(&y3);					//y3.norm();//15

        FP_BLS381_mul(&x3,&x3,&y3);			//x3.mul(y3); //16
        FP_BLS381_add(&y3,&t0,&t2);			//y3.add(t2); //y3.norm();//17

        FP_BLS381_sub(&y3,&x3,&y3);			//y3.rsub(x3);
        FP_BLS381_norm(&y3);					//y3.norm(); //18

        if (CURVE_B_I_BLS381==0)				//if (ROM.CURVE_B_I==0)
            FP_BLS381_mul(&z3,&t2,&b);			//z3.mul(b); //18
        else
            FP_BLS381_imul(&z3,&t2,CURVE_B_I_BLS381);	//z3.imul(ROM.CURVE_B_I);

        FP_BLS381_sub(&x3,&y3,&z3);			//x3.sub(z3);
        FP_BLS381_norm(&x3);					//x3.norm(); //20
        FP_BLS381_add(&z3,&x3,&x3);			//z3.add(x3); //z3.norm(); //21

        FP_BLS381_add(&x3,&x3,&z3);			//x3.add(z3); //x3.norm(); //22
        FP_BLS381_sub(&z3,&t1,&x3);			//z3.sub(x3);
        FP_BLS381_norm(&z3);					//z3.norm(); //23
        FP_BLS381_add(&x3,&x3,&t1);			//x3.add(t1);
        FP_BLS381_norm(&x3);					//x3.norm(); //24

        if (CURVE_B_I_BLS381==0)				//if (ROM.CURVE_B_I==0)
            FP_BLS381_mul(&y3,&y3,&b);			//y3.mul(b); //18
        else
            FP_BLS381_imul(&y3,&y3,CURVE_B_I_BLS381);	//y3.imul(ROM.CURVE_B_I);

        FP_BLS381_add(&t1,&t2,&t2);			//t1.add(t2); //t1.norm();//26
        FP_BLS381_add(&t2,&t2,&t1);			//t2.add(t1); //t2.norm();//27

        FP_BLS381_sub(&y3,&y3,&t2);			//y3.sub(t2); //y3.norm(); //28

        FP_BLS381_sub(&y3,&y3,&t0);			//y3.sub(t0);
        FP_BLS381_norm(&y3);					//y3.norm(); //29
        FP_BLS381_add(&t1,&y3,&y3);			//t1.add(y3); //t1.norm();//30
        FP_BLS381_add(&y3,&y3,&t1);			//y3.add(t1);
        FP_BLS381_norm(&y3);					//y3.norm(); //31

        FP_BLS381_add(&t1,&t0,&t0);			//t1.add(t0); //t1.norm(); //32
        FP_BLS381_add(&t0,&t0,&t1);			//t0.add(t1); //t0.norm();//33
        FP_BLS381_sub(&t0,&t0,&t2);			//t0.sub(t2);
        FP_BLS381_norm(&t0);					//t0.norm();//34

        FP_BLS381_mul(&t1,&t4,&y3);			//t1.mul(y3);//35
        FP_BLS381_mul(&t2,&t0,&y3);			//t2.mul(y3);//36
        FP_BLS381_mul(&y3,&x3,&z3);			//y3.mul(z3);//37
        FP_BLS381_add(&(P->y),&y3,&t2);			//y3.add(t2); //y3.norm();//38
        FP_BLS381_mul(&x3,&x3,&t3);			//x3.mul(t3);//39
        FP_BLS381_sub(&(P->x),&x3,&t1);			//x3.sub(t1);//40
        FP_BLS381_mul(&z3,&z3,&t4);			//z3.mul(t4);//41

        FP_BLS381_mul(&t1,&t3,&t0);			//t1.mul(t0);//42
        FP_BLS381_add(&(P->z),&z3,&t1);			//z3.add(t1);
        FP_BLS381_norm(&(P->x));				//x.norm();

        FP_BLS381_norm(&(P->y));				//y.norm();
        FP_BLS381_norm(&(P->z));				//z.norm();
    }

#else
    FP_BLS381 A,B,C,D,E,F,G,b;

    FP_BLS381_mul(&A,&(P->z),&(Q->z));		//A.mul(Q.z);
    FP_BLS381_sqr(&B,&A);					//B.sqr();
    FP_BLS381_mul(&C,&(P->x),&(Q->x));		//C.mul(Q.x);
    FP_BLS381_mul(&D,&(P->y),&(Q->y));		//D.mul(Q.y);
    FP_BLS381_mul(&E,&C,&D);				//E.mul(D);

    if (CURVE_B_I_BLS381==0)			//if (ROM.CURVE_B_I==0)
    {
        FP_BLS381_rcopy(&b,CURVE_B_BLS381);	//FP b=new FP(new BIG(ROM.CURVE_B));
        FP_BLS381_mul(&E,&E,&b);			//E.mul(b);
    }
    else
        FP_BLS381_imul(&E,&E,CURVE_B_I_BLS381);	//E.imul(ROM.CURVE_B_I);

    FP_BLS381_sub(&F,&B,&E);			//F.sub(E);
    FP_BLS381_add(&G,&B,&E);			//G.add(E);

    if (CURVE_A_BLS381==1)				//if (ROM.CURVE_A==1)
    {
        FP_BLS381_sub(&E,&D,&C);		//E.sub(C);
    }
    FP_BLS381_add(&C,&C,&D);			//C.add(D);
    FP_BLS381_add(&B,&(P->x),&(P->y));		//B.add(y);

    FP_BLS381_add(&D,&(Q->x),&(Q->y));		//D.add(Q.y);
    FP_BLS381_norm(&B);				//B.norm();
    FP_BLS381_norm(&D);				//D.norm();
    FP_BLS381_mul(&B,&B,&D);			//B.mul(D);
    FP_BLS381_sub(&B,&B,&C);			//B.sub(C);
    FP_BLS381_norm(&B);				//B.norm();
    FP_BLS381_norm(&F);				//F.norm();
    FP_BLS381_mul(&B,&B,&F);			//B.mul(F);
    FP_BLS381_mul(&(P->x),&A,&B); //x.mul(B);
    FP_BLS381_norm(&G);				//G.norm();

    if (CURVE_A_BLS381==1)				//if (ROM.CURVE_A==1)
    {
        FP_BLS381_norm(&E);			//E.norm();
        FP_BLS381_mul(&C,&E,&G);		//C.mul(G);
    }
    if (CURVE_A_BLS381==-1)			//if (ROM.CURVE_A==-1)
    {
        FP_BLS381_norm(&C);			//C.norm();
        FP_BLS381_mul(&C,&C,&G);		//C.mul(G);
    }
    FP_BLS381_mul(&(P->y),&A,&C);	//y.mul(C);
    FP_BLS381_mul(&(P->z),&F,&G);	//z.mul(G);

#endif
}

/* Set P-=Q */
/* SU=16 */
void  ECP_BLS381_sub(ECP_BLS381 *P,ECP_BLS381 *Q)
{
    ECP_BLS381 NQ;
    ECP_BLS381_copy(&NQ,Q);
    ECP_BLS381_neg(&NQ);
    ECP_BLS381_add(P,&NQ);
}

#endif

#if CURVETYPE_BLS381!=MONTGOMERY
/* constant time multiply by small integer of length bts - use ladder */
void ECP_BLS381_pinmul(ECP_BLS381 *P,int e,int bts)
{
    int i,b;
    ECP_BLS381 R0,R1;

    ECP_BLS381_affine(P);
    ECP_BLS381_inf(&R0);
    ECP_BLS381_copy(&R1,P);

    for (i=bts-1; i>=0; i--)
    {
        b=(e>>i)&1;
        ECP_BLS381_copy(P,&R1);
        ECP_BLS381_add(P,&R0);
        ECP_BLS381_cswap(&R0,&R1,b);
        ECP_BLS381_copy(&R1,P);
        ECP_BLS381_dbl(&R0);
        ECP_BLS381_cswap(&R0,&R1,b);
    }
    ECP_BLS381_copy(P,&R0);
    ECP_BLS381_affine(P);
}
#endif

/* Set P=r*P */
/* SU=424 */
void ECP_BLS381_mul(ECP_BLS381 *P,BIG_384_29 e)
{
#if CURVETYPE_BLS381==MONTGOMERY
    /* Montgomery ladder */
    int nb,i,b;
    ECP_BLS381 R0,R1,D;
    if (ECP_BLS381_isinf(P)) return;
    if (BIG_384_29_iszilch(e))
    {
        ECP_BLS381_inf(P);
        return;
    }

    ECP_BLS381_copy(&R0,P);
    ECP_BLS381_copy(&R1,P);
    ECP_BLS381_dbl(&R1);

    ECP_BLS381_copy(&D,P);
    ECP_BLS381_affine(&D);

    nb=BIG_384_29_nbits(e);
    for (i=nb-2; i>=0; i--)
    {
        b=BIG_384_29_bit(e,i);
        ECP_BLS381_copy(P,&R1);
        ECP_BLS381_add(P,&R0,&D);
        ECP_BLS381_cswap(&R0,&R1,b);
        ECP_BLS381_copy(&R1,P);
        ECP_BLS381_dbl(&R0);

        ECP_BLS381_cswap(&R0,&R1,b);
    }

    ECP_BLS381_copy(P,&R0);

#else
    /* fixed size windows */
    int i,nb,s,ns;
    BIG_384_29 mt,t;
    ECP_BLS381 Q,W[8],C;
    sign8 w[1+(NLEN_384_29*BASEBITS_384_29+3)/4];

    if (ECP_BLS381_isinf(P)) return;
    if (BIG_384_29_iszilch(e))
    {
        ECP_BLS381_inf(P);
        return;
    }

    ECP_BLS381_affine(P);

    /* precompute table */

    ECP_BLS381_copy(&Q,P);
    ECP_BLS381_dbl(&Q);

    ECP_BLS381_copy(&W[0],P);

    for (i=1; i<8; i++)
    {
        ECP_BLS381_copy(&W[i],&W[i-1]);
        ECP_BLS381_add(&W[i],&Q);
    }

//printf("W[1]= ");ECP_output(&W[1]); printf("\n");

    /* make exponent odd - add 2P if even, P if odd */
    BIG_384_29_copy(t,e);
    s=BIG_384_29_parity(t);
    BIG_384_29_inc(t,1);
    BIG_384_29_norm(t);
    ns=BIG_384_29_parity(t);
    BIG_384_29_copy(mt,t);
    BIG_384_29_inc(mt,1);
    BIG_384_29_norm(mt);
    BIG_384_29_cmove(t,mt,s);
    ECP_BLS381_cmove(&Q,P,ns);
    ECP_BLS381_copy(&C,&Q);

    nb=1+(BIG_384_29_nbits(t)+3)/4;

    /* convert exponent to signed 4-bit window */
    for (i=0; i<nb; i++)
    {
        w[i]=BIG_384_29_lastbits(t,5)-16;
        BIG_384_29_dec(t,w[i]);
        BIG_384_29_norm(t);
        BIG_384_29_fshr(t,4);
    }
    w[nb]=BIG_384_29_lastbits(t,5);

    ECP_BLS381_copy(P,&W[(w[nb]-1)/2]);
    for (i=nb-1; i>=0; i--)
    {
        ECP_BLS381_select(&Q,W,w[i]);
        ECP_BLS381_dbl(P);
        ECP_BLS381_dbl(P);
        ECP_BLS381_dbl(P);
        ECP_BLS381_dbl(P);
        ECP_BLS381_add(P,&Q);
    }
    ECP_BLS381_sub(P,&C); /* apply correction */
#endif
    ECP_BLS381_affine(P);
}

#if CURVETYPE_BLS381!=MONTGOMERY
/* Set P=eP+fQ double multiplication */
/* constant time - as useful for GLV method in pairings */
/* SU=456 */

void ECP_BLS381_mul2(ECP_BLS381 *P,ECP_BLS381 *Q,BIG_384_29 e,BIG_384_29 f)
{
    BIG_384_29 te,tf,mt;
    ECP_BLS381 S,T,W[8],C;
    sign8 w[1+(NLEN_384_29*BASEBITS_384_29+1)/2];
    int i,a,b,s,ns,nb;

    BIG_384_29_copy(te,e);
    BIG_384_29_copy(tf,f);

    /* precompute table */
    ECP_BLS381_copy(&W[1],P);
    ECP_BLS381_sub(&W[1],Q);  /* P+Q */
    ECP_BLS381_copy(&W[2],P);
    ECP_BLS381_add(&W[2],Q);  /* P-Q */
    ECP_BLS381_copy(&S,Q);
    ECP_BLS381_dbl(&S);  /* S=2Q */
    ECP_BLS381_copy(&W[0],&W[1]);
    ECP_BLS381_sub(&W[0],&S);
    ECP_BLS381_copy(&W[3],&W[2]);
    ECP_BLS381_add(&W[3],&S);
    ECP_BLS381_copy(&T,P);
    ECP_BLS381_dbl(&T); /* T=2P */
    ECP_BLS381_copy(&W[5],&W[1]);
    ECP_BLS381_add(&W[5],&T);
    ECP_BLS381_copy(&W[6],&W[2]);
    ECP_BLS381_add(&W[6],&T);
    ECP_BLS381_copy(&W[4],&W[5]);
    ECP_BLS381_sub(&W[4],&S);
    ECP_BLS381_copy(&W[7],&W[6]);
    ECP_BLS381_add(&W[7],&S);

    /* if multiplier is odd, add 2, else add 1 to multiplier, and add 2P or P to correction */

    s=BIG_384_29_parity(te);
    BIG_384_29_inc(te,1);
    BIG_384_29_norm(te);
    ns=BIG_384_29_parity(te);
    BIG_384_29_copy(mt,te);
    BIG_384_29_inc(mt,1);
    BIG_384_29_norm(mt);
    BIG_384_29_cmove(te,mt,s);
    ECP_BLS381_cmove(&T,P,ns);
    ECP_BLS381_copy(&C,&T);

    s=BIG_384_29_parity(tf);
    BIG_384_29_inc(tf,1);
    BIG_384_29_norm(tf);
    ns=BIG_384_29_parity(tf);
    BIG_384_29_copy(mt,tf);
    BIG_384_29_inc(mt,1);
    BIG_384_29_norm(mt);
    BIG_384_29_cmove(tf,mt,s);
    ECP_BLS381_cmove(&S,Q,ns);
    ECP_BLS381_add(&C,&S);

    BIG_384_29_add(mt,te,tf);
    BIG_384_29_norm(mt);
    nb=1+(BIG_384_29_nbits(mt)+1)/2;

    /* convert exponent to signed 2-bit window */
    for (i=0; i<nb; i++)
    {
        a=BIG_384_29_lastbits(te,3)-4;
        BIG_384_29_dec(te,a);
        BIG_384_29_norm(te);
        BIG_384_29_fshr(te,2);
        b=BIG_384_29_lastbits(tf,3)-4;
        BIG_384_29_dec(tf,b);
        BIG_384_29_norm(tf);
        BIG_384_29_fshr(tf,2);
        w[i]=4*a+b;
    }
    w[nb]=(4*BIG_384_29_lastbits(te,3)+BIG_384_29_lastbits(tf,3));

    ECP_BLS381_copy(P,&W[(w[nb]-1)/2]);
    for (i=nb-1; i>=0; i--)
    {
        ECP_BLS381_select(&T,W,w[i]);
        ECP_BLS381_dbl(P);
        ECP_BLS381_dbl(P);
        ECP_BLS381_add(P,&T);
    }
    ECP_BLS381_sub(P,&C); /* apply correction */
    ECP_BLS381_affine(P);
}

#endif

void ECP_BLS381_generator(ECP_BLS381 *G)
{
    BIG_384_29 x,y;
    BIG_384_29_rcopy(x,CURVE_Gx_BLS381);
#if CURVETYPE_BLS381!=MONTGOMERY
    BIG_384_29_rcopy(y,CURVE_Gy_BLS381);
    ECP_BLS381_set(G,x,y);
#else
    ECP_BLS381_set(G,x);
#endif
}

#ifdef HAS_MAIN

int main()
{
    int i;
    ECP_BLS381 G,P;
    csprng RNG;
    BIG_384_29 r,s,x,y,b,m,w,q;
    BIG_384_29_rcopy(x,CURVE_Gx);
#if CURVETYPE_BLS381!=MONTGOMERY
    BIG_384_29_rcopy(y,CURVE_Gy);
#endif
    BIG_384_29_rcopy(m,Modulus_BLS381);

    printf("x= ");
    BIG_384_29_output(x);
    printf("\n");
#if CURVETYPE_BLS381!=MONTGOMERY
    printf("y= ");
    BIG_384_29_output(y);
    printf("\n");
#endif
    RNG_seed(&RNG,3,"abc");

#if CURVETYPE_BLS381!=MONTGOMERY
    ECP_BLS381_set(&G,x,y);
#else
    ECP_BLS381_set(&G,x);
#endif
    if (ECP_BLS381_isinf(&G)) printf("Failed to set - point not on curve\n");
    else printf("set success\n");

    ECP_BLS381_output(&G);

    BIG_384_29_rcopy(r,CURVE_Order); //BIG_dec(r,7);
    printf("r= ");
    BIG_384_29_output(r);
    printf("\n");

    ECP_BLS381_copy(&P,&G);

    ECP_BLS381_mul(&P,r);

    ECP_BLS381_output(&P);
//exit(0);
    BIG_384_29_randomnum(w,&RNG);
    BIG_384_29_mod(w,r);

    ECP_BLS381_copy(&P,&G);
    ECP_BLS381_mul(&P,w);

    ECP_BLS381_output(&P);

    return 0;
}

#endif
