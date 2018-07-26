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

/* AMCL Weierstrass elliptic curve functions over FP2 */
/* SU=m, m is Stack Usage */

#include "ecp2_BLS381.h"

int ECP2_BLS381_isinf(ECP2_BLS381 *P)
{
//    if (P->inf) return 1;
    return (FP2_BLS381_iszilch(&(P->x)) & FP2_BLS381_iszilch(&(P->z)));
}

/* Set P=Q */
/* SU= 16 */
void ECP2_BLS381_copy(ECP2_BLS381 *P,ECP2_BLS381 *Q)
{
//    P->inf=Q->inf;
    FP2_BLS381_copy(&(P->x),&(Q->x));
    FP2_BLS381_copy(&(P->y),&(Q->y));
    FP2_BLS381_copy(&(P->z),&(Q->z));
}

/* set P to Infinity */
/* SU= 8 */
void ECP2_BLS381_inf(ECP2_BLS381 *P)
{
//    P->inf=1;
    FP2_BLS381_zero(&(P->x));
    FP2_BLS381_one(&(P->y));
    FP2_BLS381_zero(&(P->z));
}

/* Conditional move Q to P dependant on d */
static void ECP2_BLS381_cmove(ECP2_BLS381 *P,ECP2_BLS381 *Q,int d)
{
    FP2_BLS381_cmove(&(P->x),&(Q->x),d);
    FP2_BLS381_cmove(&(P->y),&(Q->y),d);
    FP2_BLS381_cmove(&(P->z),&(Q->z),d);
//    d=~(d-1);
//    P->inf^=(P->inf^Q->inf)&d;
}

/* return 1 if b==c, no branching */
static int teq(sign32 b,sign32 c)
{
    sign32 x=b^c;
    x-=1;  // if x=0, x now -1
    return (int)((x>>31)&1);
}

/* Constant time select from pre-computed table */
static void ECP2_BLS381_select(ECP2_BLS381 *P,ECP2_BLS381 W[],sign32 b)
{
    ECP2_BLS381 MP;
    sign32 m=b>>31;
    sign32 babs=(b^m)-m;

    babs=(babs-1)/2;

    ECP2_BLS381_cmove(P,&W[0],teq(babs,0));  // conditional move
    ECP2_BLS381_cmove(P,&W[1],teq(babs,1));
    ECP2_BLS381_cmove(P,&W[2],teq(babs,2));
    ECP2_BLS381_cmove(P,&W[3],teq(babs,3));
    ECP2_BLS381_cmove(P,&W[4],teq(babs,4));
    ECP2_BLS381_cmove(P,&W[5],teq(babs,5));
    ECP2_BLS381_cmove(P,&W[6],teq(babs,6));
    ECP2_BLS381_cmove(P,&W[7],teq(babs,7));

    ECP2_BLS381_copy(&MP,P);
    ECP2_BLS381_neg(&MP);  // minus P
    ECP2_BLS381_cmove(P,&MP,(int)(m&1));
}

/* return 1 if P==Q, else 0 */
/* SU= 312 */
int ECP2_BLS381_equals(ECP2_BLS381 *P,ECP2_BLS381 *Q)
{
    FP2_BLS381 a,b;
//    if (ECP2_BLS381_isinf(P) && ECP2_BLS381_isinf(Q)) return 1;
//    if (ECP2_BLS381_isinf(P) || ECP2_BLS381_isinf(Q)) return 0;

    FP2_BLS381_mul(&a,&(P->x),&(Q->z));
    FP2_BLS381_mul(&b,&(Q->x),&(P->z));
    if (!FP2_BLS381_equals(&a,&b)) return 0;

    FP2_BLS381_mul(&a,&(P->y),&(Q->z));
    FP2_BLS381_mul(&b,&(Q->y),&(P->z));
    if (!FP2_BLS381_equals(&a,&b)) return 0;
    return 1;
}

/* Make P affine (so z=1) */
/* SU= 232 */
void ECP2_BLS381_affine(ECP2_BLS381 *P)
{
    FP2_BLS381 one,iz;
    if (ECP2_BLS381_isinf(P)) return;

    FP2_BLS381_one(&one);
    if (FP2_BLS381_isunity(&(P->z)))
    {
        FP2_BLS381_reduce(&(P->x));
        FP2_BLS381_reduce(&(P->y));
        return;
    }

    FP2_BLS381_inv(&iz,&(P->z));
    FP2_BLS381_mul(&(P->x),&(P->x),&iz);
    FP2_BLS381_mul(&(P->y),&(P->y),&iz);

    FP2_BLS381_reduce(&(P->x));
    FP2_BLS381_reduce(&(P->y));
    FP2_BLS381_copy(&(P->z),&one);
}

/* extract x, y from point P */
/* SU= 16 */
int ECP2_BLS381_get(FP2_BLS381 *x,FP2_BLS381 *y,ECP2_BLS381 *P)
{
    if (ECP2_BLS381_isinf(P)) return -1;
    ECP2_BLS381_affine(P);
    FP2_BLS381_copy(y,&(P->y));
    FP2_BLS381_copy(x,&(P->x));
    return 0;
}

/* SU= 152 */
/* Output point P */
void ECP2_BLS381_output(ECP2_BLS381 *P)
{
    FP2_BLS381 x,y;
    if (ECP2_BLS381_isinf(P))
    {
        printf("Infinity\n");
        return;
    }
    ECP2_BLS381_get(&x,&y,P);
    printf("(");
    FP2_BLS381_output(&x);
    printf(",");
    FP2_BLS381_output(&y);
    printf(")\n");
}

/* SU= 232 */
void ECP2_BLS381_outputxyz(ECP2_BLS381 *P)
{
    ECP2_BLS381 Q;
    if (ECP2_BLS381_isinf(P))
    {
        printf("Infinity\n");
        return;
    }
    ECP2_BLS381_copy(&Q,P);
    printf("(");
    FP2_BLS381_output(&(Q.x));
    printf(",");
    FP2_BLS381_output(&(Q.y));
    printf(",");
    FP2_BLS381_output(&(Q.z));
    printf(")\n");
}

/* SU= 168 */
/* Convert Q to octet string */
void ECP2_BLS381_toOctet(octet *W,ECP2_BLS381 *Q)
{
    BIG_384_29 b;
    FP2_BLS381 qx,qy;
    ECP2_BLS381_get(&qx,&qy,Q);

    FP_BLS381_redc(b,&(qx.a));
    BIG_384_29_toBytes(&(W->val[0]),b);
    FP_BLS381_redc(b,&(qx.b));
    BIG_384_29_toBytes(&(W->val[MODBYTES_384_29]),b);
    FP_BLS381_redc(b,&(qy.a));
    BIG_384_29_toBytes(&(W->val[2*MODBYTES_384_29]),b);
    FP_BLS381_redc(b,&(qy.b));
    BIG_384_29_toBytes(&(W->val[3*MODBYTES_384_29]),b);

    W->len=4*MODBYTES_384_29;

}

/* SU= 176 */
/* restore Q from octet string */
int ECP2_BLS381_fromOctet(ECP2_BLS381 *Q,octet *W)
{
    BIG_384_29 b;
    FP2_BLS381 qx,qy;
    BIG_384_29_fromBytes(b,&(W->val[0]));
    FP_BLS381_nres(&(qx.a),b);
    BIG_384_29_fromBytes(b,&(W->val[MODBYTES_384_29]));
    FP_BLS381_nres(&(qx.b),b);
    BIG_384_29_fromBytes(b,&(W->val[2*MODBYTES_384_29]));
    FP_BLS381_nres(&(qy.a),b);
    BIG_384_29_fromBytes(b,&(W->val[3*MODBYTES_384_29]));
    FP_BLS381_nres(&(qy.b),b);

    if (ECP2_BLS381_set(Q,&qx,&qy)) return 1;
    return 0;
}

/* SU= 128 */
/* Calculate RHS of twisted curve equation x^3+B/i or x^3+Bi*/
void ECP2_BLS381_rhs(FP2_BLS381 *rhs,FP2_BLS381 *x)
{
    /* calculate RHS of elliptic curve equation */
    FP2_BLS381 t;
    BIG_384_29 b;
    FP2_BLS381_sqr(&t,x);

    FP2_BLS381_mul(rhs,&t,x);

    /* Assuming CURVE_A=0 */

    BIG_384_29_rcopy(b,CURVE_B_BLS381);

    FP2_BLS381_from_BIG(&t,b);

#if SEXTIC_TWIST_BLS381 == D_TYPE
    FP2_BLS381_div_ip(&t);   /* IMPORTANT - here we use the correct SEXTIC twist of the curve */
#endif

#if SEXTIC_TWIST_BLS381 == M_TYPE
    FP2_BLS381_norm(&t);
    FP2_BLS381_mul_ip(&t);   /* IMPORTANT - here we use the correct SEXTIC twist of the curve */
    FP2_BLS381_norm(&t);

#endif


    FP2_BLS381_add(rhs,&t,rhs);
    FP2_BLS381_reduce(rhs);
}


/* Set P=(x,y). Return 1 if (x,y) is on the curve, else return 0*/
/* SU= 232 */
int ECP2_BLS381_set(ECP2_BLS381 *P,FP2_BLS381 *x,FP2_BLS381 *y)
{
    FP2_BLS381 rhs,y2;

    FP2_BLS381_sqr(&y2,y);
    ECP2_BLS381_rhs(&rhs,x);

    if (!FP2_BLS381_equals(&y2,&rhs))
    {
		ECP2_BLS381_inf(P);
       // P->inf=1;
        return 0;
    }

  //  P->inf=0;
    FP2_BLS381_copy(&(P->x),x);
    FP2_BLS381_copy(&(P->y),y);

    FP2_BLS381_one(&(P->z));
    return 1;
}

/* Set P=(x,y). Return 1 if (x,.) is on the curve, else return 0 */
/* SU= 232 */
int ECP2_BLS381_setx(ECP2_BLS381 *P,FP2_BLS381 *x)
{
    FP2_BLS381 y;
    ECP2_BLS381_rhs(&y,x);

    if (!FP2_BLS381_sqrt(&y,&y))
    {
		ECP2_BLS381_inf(P);
        return 0;
    }

 //   P->inf=0;
    FP2_BLS381_copy(&(P->x),x);
    FP2_BLS381_copy(&(P->y),&y);
    FP2_BLS381_one(&(P->z));
    return 1;
}

/* Set P=-P */
/* SU= 8 */
void ECP2_BLS381_neg(ECP2_BLS381 *P)
{
//	if (ECP2_BLS381_isinf(P)) return;
    FP2_BLS381_norm(&(P->y));
    FP2_BLS381_neg(&(P->y),&(P->y));
    FP2_BLS381_norm(&(P->y));
}

/* R+=R */
/* return -1 for Infinity, 0 for addition, 1 for doubling */
/* SU= 448 */
int ECP2_BLS381_dbl(ECP2_BLS381 *P)
{
    FP2_BLS381 t0,t1,t2,iy,x3,y3;
//    if (P->inf) return -1;

    FP2_BLS381_copy(&iy,&(P->y));		//FP2 iy=new FP2(y);
#if SEXTIC_TWIST_BLS381==D_TYPE
    FP2_BLS381_mul_ip(&iy);			//iy.mul_ip();
    FP2_BLS381_norm(&iy);				//iy.norm();
#endif
    //FP2_BLS381_copy(&t0,&(P->y));		//FP2 t0=new FP2(y);                  //***** Change
    FP2_BLS381_sqr(&t0,&(P->y));			//t0.sqr();
#if SEXTIC_TWIST_BLS381==D_TYPE
    FP2_BLS381_mul_ip(&t0);			//t0.mul_ip();
#endif
    //FP2_BLS381_copy(&t1,&iy);				//FP2 t1=new FP2(iy);
    FP2_BLS381_mul(&t1,&iy,&(P->z));	//t1.mul(z);
    //FP2_BLS381_copy(&t2,&(P->z));		//FP2 t2=new FP2(z);
    FP2_BLS381_sqr(&t2,&(P->z));				//t2.sqr();

    //FP2_BLS381_copy(&(P->z),&t0);		//z.copy(t0);
    FP2_BLS381_add(&(P->z),&t0,&t0);	//z.add(t0);
    FP2_BLS381_norm(&(P->z));				//z.norm();
    FP2_BLS381_add(&(P->z),&(P->z),&(P->z));	//z.add(z);
    FP2_BLS381_add(&(P->z),&(P->z),&(P->z));	//z.add(z);
    FP2_BLS381_norm(&(P->z));			//z.norm();

    FP2_BLS381_imul(&t2,&t2,3*CURVE_B_I_BLS381);	//t2.imul(3*ROM.CURVE_B_I);
#if SEXTIC_TWIST_BLS381==M_TYPE
    FP2_BLS381_mul_ip(&t2);
    FP2_BLS381_norm(&t2);
#endif

    //FP2_BLS381_copy(&x3,&t2);			//FP2 x3=new FP2(t2);
    FP2_BLS381_mul(&x3,&t2,&(P->z));	//x3.mul(z);

    //FP2_BLS381_copy(&y3,&t0);			//FP2 y3=new FP2(t0);

    FP2_BLS381_add(&y3,&t0,&t2);		//y3.add(t2);
    FP2_BLS381_norm(&y3);				//y3.norm();
    FP2_BLS381_mul(&(P->z),&(P->z),&t1);	//z.mul(t1);

    //FP2_BLS381_copy(&t1,&t2);			//t1.copy(t2);
    FP2_BLS381_add(&t1,&t2,&t2);		//t1.add(t2);
    FP2_BLS381_add(&t2,&t2,&t1);		//t2.add(t1);
    FP2_BLS381_norm(&t2);				//t2.norm();
    FP2_BLS381_sub(&t0,&t0,&t2);		//t0.sub(t2);
    FP2_BLS381_norm(&t0);				//t0.norm();                           //y^2-9bz^2
    FP2_BLS381_mul(&y3,&y3,&t0);		//y3.mul(t0);
    FP2_BLS381_add(&(P->y),&y3,&x3);		//y3.add(x3);                          //(y^2+3z*2)(y^2-9z^2)+3b.z^2.8y^2
    //FP2_BLS381_copy(&t1,&(P->x));		//t1.copy(x);
    FP2_BLS381_mul(&t1,&(P->x),&iy);		//t1.mul(iy);						//
    //FP2_BLS381_copy(&(P->x),&t0);		//x.copy(t0);
    FP2_BLS381_norm(&t0);			//x.norm();
    FP2_BLS381_mul(&(P->x),&t0,&t1);	//x.mul(t1);
    FP2_BLS381_add(&(P->x),&(P->x),&(P->x));	//x.add(x);       //(y^2-9bz^2)xy2

    FP2_BLS381_norm(&(P->x));			//x.norm();
    //FP2_BLS381_copy(&(P->y),&y3);		//y.copy(y3);
    FP2_BLS381_norm(&(P->y));			//y.norm();

    return 1;
}

/* Set P+=Q */
/* SU= 400 */
int ECP2_BLS381_add(ECP2_BLS381 *P,ECP2_BLS381 *Q)
{
    FP2_BLS381 t0,t1,t2,t3,t4,x3,y3,z3;
    int b3=3*CURVE_B_I_BLS381;
/*    if (Q->inf) return 0;
    if (P->inf)
    {
        ECP2_BLS381_copy(P,Q);
        return 0;
    }
*/
    //FP2_BLS381_copy(&t0,&(P->x));		//FP2 t0=new FP2(x);
    FP2_BLS381_mul(&t0,&(P->x),&(Q->x));	//t0.mul(Q.x);         // x.Q.x
    //FP2_BLS381_copy(&t1,&(P->y));		//FP2 t1=new FP2(y);
    FP2_BLS381_mul(&t1,&(P->y),&(Q->y));	//t1.mul(Q.y);		 // y.Q.y

    //FP2_BLS381_copy(&t2,&(P->z));		//FP2 t2=new FP2(z);
    FP2_BLS381_mul(&t2,&(P->z),&(Q->z));	//t2.mul(Q.z);
    //FP2_BLS381_copy(&t3,&(P->x));		//FP2 t3=new FP2(x);
    FP2_BLS381_add(&t3,&(P->x),&(P->y));	//t3.add(y);
    FP2_BLS381_norm(&t3);				//t3.norm();          //t3=X1+Y1
    //FP2_BLS381_copy(&t4,&(Q->x));		//FP2 t4=new FP2(Q.x);
    FP2_BLS381_add(&t4,&(Q->x),&(Q->y));	//t4.add(Q.y);
    FP2_BLS381_norm(&t4);				//t4.norm();			//t4=X2+Y2
    FP2_BLS381_mul(&t3,&t3,&t4);		//t3.mul(t4);						//t3=(X1+Y1)(X2+Y2)
    //FP2_BLS381_copy(&t4,&t0);			//t4.copy(t0);
    FP2_BLS381_add(&t4,&t0,&t1);		//t4.add(t1);		//t4=X1.X2+Y1.Y2

    FP2_BLS381_sub(&t3,&t3,&t4);		//t3.sub(t4);
    FP2_BLS381_norm(&t3);				//t3.norm();
#if SEXTIC_TWIST_BLS381==D_TYPE
    FP2_BLS381_mul_ip(&t3);			//t3.mul_ip();
    FP2_BLS381_norm(&t3);				//t3.norm();         //t3=(X1+Y1)(X2+Y2)-(X1.X2+Y1.Y2) = X1.Y2+X2.Y1
#endif
    //FP2_BLS381_copy(&t4,&(P->y));		//t4.copy(y);
    FP2_BLS381_add(&t4,&(P->y),&(P->z));	//t4.add(z);
    FP2_BLS381_norm(&t4);				//t4.norm();			//t4=Y1+Z1
    //FP2_BLS381_copy(&x3,&(Q->y));		//FP2 x3=new FP2(Q.y);
    FP2_BLS381_add(&x3,&(Q->y),&(Q->z));	//x3.add(Q.z);
    FP2_BLS381_norm(&x3);				//x3.norm();			//x3=Y2+Z2

    FP2_BLS381_mul(&t4,&t4,&x3);		//t4.mul(x3);						//t4=(Y1+Z1)(Y2+Z2)
    //FP2_BLS381_copy(&x3,&t1);			//x3.copy(t1);					//
    FP2_BLS381_add(&x3,&t1,&t2);		//x3.add(t2);						//X3=Y1.Y2+Z1.Z2

    FP2_BLS381_sub(&t4,&t4,&x3);		//t4.sub(x3);
    FP2_BLS381_norm(&t4);				//t4.norm();
#if SEXTIC_TWIST_BLS381==D_TYPE
    FP2_BLS381_mul_ip(&t4);			//t4.mul_ip();
    FP2_BLS381_norm(&t4);				//t4.norm();          //t4=(Y1+Z1)(Y2+Z2) - (Y1.Y2+Z1.Z2) = Y1.Z2+Y2.Z1
#endif
    //FP2_BLS381_copy(&x3,&(P->x));		//x3.copy(x);
    FP2_BLS381_add(&x3,&(P->x),&(P->z));	//x3.add(z);
    FP2_BLS381_norm(&x3);				//x3.norm();	// x3=X1+Z1
    //FP2_BLS381_copy(&y3,&(Q->x));		//FP2 y3=new FP2(Q.x);
    FP2_BLS381_add(&y3,&(Q->x),&(Q->z));	//y3.add(Q.z);
    FP2_BLS381_norm(&y3);				//y3.norm();				// y3=X2+Z2
    FP2_BLS381_mul(&x3,&x3,&y3);		//x3.mul(y3);							// x3=(X1+Z1)(X2+Z2)
    //FP2_BLS381_copy(&y3,&t0);			//y3.copy(t0);
    FP2_BLS381_add(&y3,&t0,&t2);		//y3.add(t2);							// y3=X1.X2+Z1+Z2
    FP2_BLS381_sub(&y3,&x3,&y3);		//y3.rsub(x3);
    FP2_BLS381_norm(&y3);				//y3.norm();				// y3=(X1+Z1)(X2+Z2) - (X1.X2+Z1.Z2) = X1.Z2+X2.Z1
#if SEXTIC_TWIST_BLS381==D_TYPE
    FP2_BLS381_mul_ip(&t0);			//t0.mul_ip();
    FP2_BLS381_norm(&t0);				//t0.norm(); // x.Q.x
    FP2_BLS381_mul_ip(&t1);			//t1.mul_ip();
    FP2_BLS381_norm(&t1);				//t1.norm(); // y.Q.y
#endif
    //FP2_BLS381_copy(&x3,&t0);			//x3.copy(t0);
    FP2_BLS381_add(&x3,&t0,&t0);		//x3.add(t0);
    FP2_BLS381_add(&t0,&t0,&x3);		//t0.add(x3);
    FP2_BLS381_norm(&t0);				//t0.norm();
    FP2_BLS381_imul(&t2,&t2,b3);		//t2.imul(b);
#if SEXTIC_TWIST_BLS381==M_TYPE
    FP2_BLS381_mul_ip(&t2);
#endif
    //FP2_BLS381_copy(&z3,&t1);			//FP2 z3=new FP2(t1);
    FP2_BLS381_add(&z3,&t1,&t2);		//z3.add(t2);
    FP2_BLS381_norm(&z3);				//z3.norm();
    FP2_BLS381_sub(&t1,&t1,&t2);		//t1.sub(t2);
    FP2_BLS381_norm(&t1);				//t1.norm();
    FP2_BLS381_imul(&y3,&y3,b3);		//y3.imul(b);
#if SEXTIC_TWIST_BLS381==M_TYPE
    FP2_BLS381_mul_ip(&y3);
    FP2_BLS381_norm(&y3);
#endif
    //FP2_BLS381_copy(&x3,&y3);			//x3.copy(y3);
    FP2_BLS381_mul(&x3,&y3,&t4);		//x3.mul(t4);
    //FP2_BLS381_copy(&t2,&t3);			//t2.copy(t3);
    FP2_BLS381_mul(&t2,&t3,&t1);		//t2.mul(t1);
    FP2_BLS381_sub(&(P->x),&t2,&x3);		//x3.rsub(t2);
    FP2_BLS381_mul(&y3,&y3,&t0);		//y3.mul(t0);
    FP2_BLS381_mul(&t1,&t1,&z3);		//t1.mul(z3);
    FP2_BLS381_add(&(P->y),&y3,&t1);		//y3.add(t1);
    FP2_BLS381_mul(&t0,&t0,&t3);		//t0.mul(t3);
    FP2_BLS381_mul(&z3,&z3,&t4);		//z3.mul(t4);
    FP2_BLS381_add(&(P->z),&z3,&t0);		//z3.add(t0);

    //FP2_BLS381_copy(&(P->x),&x3);		//x.copy(x3);
    FP2_BLS381_norm(&(P->x));			//x.norm();
    //FP2_BLS381_copy(&(P->y),&y3);		//y.copy(y3);
    FP2_BLS381_norm(&(P->y));			//y.norm();
    //FP2_BLS381_copy(&(P->z),&z3);		//z.copy(z3);
    FP2_BLS381_norm(&(P->z));			//z.norm();

    return 0;
}

/* Set P-=Q */
/* SU= 16 */
void ECP2_BLS381_sub(ECP2_BLS381 *P,ECP2_BLS381 *Q)
{
    ECP2_BLS381_neg(Q);
    ECP2_BLS381_add(P,Q);
    ECP2_BLS381_neg(Q);
}

/* P*=e */
/* SU= 280 */
void ECP2_BLS381_mul(ECP2_BLS381 *P,BIG_384_29 e)
{
    /* fixed size windows */
    int i,nb,s,ns;
    BIG_384_29 mt,t;
    ECP2_BLS381 Q,W[8],C;
    sign8 w[1+(NLEN_384_29*BASEBITS_384_29+3)/4];

    if (ECP2_BLS381_isinf(P)) return;
    ECP2_BLS381_affine(P);


    /* precompute table */

    ECP2_BLS381_copy(&Q,P);
    ECP2_BLS381_dbl(&Q);
    ECP2_BLS381_copy(&W[0],P);

    for (i=1; i<8; i++)
    {
        ECP2_BLS381_copy(&W[i],&W[i-1]);
        ECP2_BLS381_add(&W[i],&Q);
    }

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
    ECP2_BLS381_cmove(&Q,P,ns);
    ECP2_BLS381_copy(&C,&Q);

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

    ECP2_BLS381_copy(P,&W[(w[nb]-1)/2]);
    for (i=nb-1; i>=0; i--)
    {
        ECP2_BLS381_select(&Q,W,w[i]);
        ECP2_BLS381_dbl(P);
        ECP2_BLS381_dbl(P);
        ECP2_BLS381_dbl(P);
        ECP2_BLS381_dbl(P);
        ECP2_BLS381_add(P,&Q);
    }
    ECP2_BLS381_sub(P,&C); /* apply correction */
    ECP2_BLS381_affine(P);
}

/* Calculates q.P using Frobenius constant X */
/* SU= 96 */
void ECP2_BLS381_frob(ECP2_BLS381 *P,FP2_BLS381 *X)
{
    FP2_BLS381 X2;
//    if (P->inf) return;
//printf("X= "); FP2_BLS381_output(X); printf("\n");
    FP2_BLS381_sqr(&X2,X);
//printf("X2= "); FP2_BLS381_output(&X2); printf("\n");
    FP2_BLS381_conj(&(P->x),&(P->x));
    FP2_BLS381_conj(&(P->y),&(P->y));
    FP2_BLS381_conj(&(P->z),&(P->z));
    FP2_BLS381_reduce(&(P->z));

    FP2_BLS381_mul(&(P->x),&X2,&(P->x));
    FP2_BLS381_mul(&(P->y),&X2,&(P->y));
    FP2_BLS381_mul(&(P->y),X,&(P->y));


//printf("Px= "); FP2_BLS381_output(&(P->x)); printf("\n");
//printf("Py= "); FP2_BLS381_output(&(P->y)); printf("\n");
//printf("Pz= "); FP2_BLS381_output(&(P->z)); printf("\n");
}


// Bos & Costello https://eprint.iacr.org/2013/458.pdf
// Faz-Hernandez & Longa & Sanchez  https://eprint.iacr.org/2013/158.pdf
// Side channel attack secure 

void ECP2_BLS381_mul4(ECP2_BLS381 *P,ECP2_BLS381 Q[4],BIG_384_29 u[4])
{
    int i,j,k,nb,pb,bt;
	ECP2_BLS381 T[8],W;
    BIG_384_29 t[4],mt;
	sign8 w[NLEN_384_29*BASEBITS_384_29+1];
	sign8 s[NLEN_384_29*BASEBITS_384_29+1];

    for (i=0; i<4; i++)
    {
        BIG_384_29_copy(t[i],u[i]);
        ECP2_BLS381_affine(&Q[i]);
    }

// Precomputed table
    ECP2_BLS381_copy(&T[0],&Q[0]); // Q[0]
    ECP2_BLS381_copy(&T[1],&T[0]);
	ECP2_BLS381_add(&T[1],&Q[1]);	// Q[0]+Q[1]
    ECP2_BLS381_copy(&T[2],&T[0]);
	ECP2_BLS381_add(&T[2],&Q[2]);	// Q[0]+Q[2]
	ECP2_BLS381_copy(&T[3],&T[1]);
	ECP2_BLS381_add(&T[3],&Q[2]);	// Q[0]+Q[1]+Q[2]
	ECP2_BLS381_copy(&T[4],&T[0]);
	ECP2_BLS381_add(&T[4],&Q[3]);  // Q[0]+Q[3]
	ECP2_BLS381_copy(&T[5],&T[1]);
	ECP2_BLS381_add(&T[5],&Q[3]);	// Q[0]+Q[1]+Q[3]
	ECP2_BLS381_copy(&T[6],&T[2]);
	ECP2_BLS381_add(&T[6],&Q[3]);	// Q[0]+Q[2]+Q[3]
	ECP2_BLS381_copy(&T[7],&T[3]);
	ECP2_BLS381_add(&T[7],&Q[3]);	// Q[0]+Q[1]+Q[2]+Q[3]

// Make it odd
	pb=1-BIG_384_29_parity(t[0]);
	BIG_384_29_inc(t[0],pb);
	BIG_384_29_norm(t[0]);

// Number of bits
    BIG_384_29_zero(mt);
    for (i=0; i<4; i++)
    {
        BIG_384_29_or(mt,mt,t[i]);
    }
    nb=1+BIG_384_29_nbits(mt);

// Sign pivot 
	s[nb-1]=1;
	for (i=0;i<nb-1;i++)
	{
        BIG_384_29_fshr(t[0],1);
		s[i]=2*BIG_384_29_parity(t[0])-1;
	}

// Recoded exponent
    for (i=0; i<nb; i++)
    {
		w[i]=0;
		k=1;
		for (j=1; j<4; j++)
		{
			bt=s[i]*BIG_384_29_parity(t[j]);
			BIG_384_29_fshr(t[j],1);

			BIG_384_29_dec(t[j],(bt>>1));
			BIG_384_29_norm(t[j]);
			w[i]+=bt*k;
			k*=2;
        }
    }		

// Main loop
	ECP2_BLS381_select(P,T,2*w[nb-1]+1);
    for (i=nb-2; i>=0; i--)
    {
        ECP2_BLS381_select(&W,T,2*w[i]+s[i]);
        ECP2_BLS381_dbl(P);
        ECP2_BLS381_add(P,&W);
    }

// apply correction
	ECP2_BLS381_copy(&W,P);   
	ECP2_BLS381_sub(&W,&Q[0]);
	ECP2_BLS381_cmove(P,&W,pb);

    ECP2_BLS381_affine(P);
}


/*
void ECP2_BLS381_mul4(ECP2_BLS381 *P,ECP2_BLS381 Q[4],BIG_384_29 u[4])
{
    int i,j,a[4],nb;
    ECP2_BLS381 W[8],T,C;
    BIG_384_29 mt,t[4];
    sign8 w[NLEN_384_29*BASEBITS_384_29+1];

    for (i=0; i<4; i++)
    {
        BIG_384_29_copy(t[i],u[i]);
        ECP2_BLS381_affine(&Q[i]);
    }

    // precompute table 

    ECP2_BLS381_copy(&W[0],&Q[0]);
    ECP2_BLS381_sub(&W[0],&Q[1]);  // P-Q 
    ECP2_BLS381_copy(&W[1],&W[0]);
    ECP2_BLS381_copy(&W[2],&W[0]);
    ECP2_BLS381_copy(&W[3],&W[0]);
    ECP2_BLS381_copy(&W[4],&Q[0]);
    ECP2_BLS381_add(&W[4],&Q[1]);  // P+Q 
    ECP2_BLS381_copy(&W[5],&W[4]);
    ECP2_BLS381_copy(&W[6],&W[4]);
    ECP2_BLS381_copy(&W[7],&W[4]);

    ECP2_BLS381_copy(&T,&Q[2]);
    ECP2_BLS381_sub(&T,&Q[3]);       // R-S 
    ECP2_BLS381_sub(&W[1],&T);
    ECP2_BLS381_add(&W[2],&T);
    ECP2_BLS381_sub(&W[5],&T);
    ECP2_BLS381_add(&W[6],&T);
    ECP2_BLS381_copy(&T,&Q[2]);
    ECP2_BLS381_add(&T,&Q[3]);      // R+S 
    ECP2_BLS381_sub(&W[0],&T);
    ECP2_BLS381_add(&W[3],&T);
    ECP2_BLS381_sub(&W[4],&T);
    ECP2_BLS381_add(&W[7],&T);

    // if multiplier is even add 1 to multiplier, and add P to correction 
    ECP2_BLS381_inf(&C);

    BIG_384_29_zero(mt);
    for (i=0; i<4; i++)
    {
        if (BIG_384_29_parity(t[i])==0)
        {
            BIG_384_29_inc(t[i],1);
            BIG_384_29_norm(t[i]);
            ECP2_BLS381_add(&C,&Q[i]);
        }
        BIG_384_29_add(mt,mt,t[i]);
        BIG_384_29_norm(mt);
    }

    nb=1+BIG_384_29_nbits(mt);

    // convert exponent to signed 1-bit window 
    for (j=0; j<nb; j++)
    {
        for (i=0; i<4; i++)
        {
            a[i]=BIG_384_29_lastbits(t[i],2)-2;
            BIG_384_29_dec(t[i],a[i]);
            BIG_384_29_norm(t[i]);
            BIG_384_29_fshr(t[i],1);
        }
        w[j]=8*a[0]+4*a[1]+2*a[2]+a[3];
    }
    w[nb]=8*BIG_384_29_lastbits(t[0],2)+4*BIG_384_29_lastbits(t[1],2)+2*BIG_384_29_lastbits(t[2],2)+BIG_384_29_lastbits(t[3],2);

    ECP2_BLS381_copy(P,&W[(w[nb]-1)/2]);
    for (i=nb-1; i>=0; i--)
    {
        ECP2_BLS381_select(&T,W,w[i]);
        ECP2_BLS381_dbl(P);
        ECP2_BLS381_add(P,&T);
    }
    ECP2_BLS381_sub(P,&C); // apply correction 

    ECP2_BLS381_affine(P);
}
*/

/* Map to hash value to point on G2 from random BIG */
void ECP2_BLS381_mapit(ECP2_BLS381 *Q,octet *W)
{
    BIG_384_29 q,one,Fx,Fy,x,hv;
    FP2_BLS381 X;
#if (PAIRING_FRIENDLY_BLS381 == BN)
    ECP2_BLS381 T,K;
#elif (PAIRING_FRIENDLY_BLS381 == BLS)
    ECP2_BLS381 xQ, x2Q;
#endif
    BIG_384_29_fromBytes(hv,W->val);
    BIG_384_29_rcopy(q,Modulus_BLS381);
    BIG_384_29_one(one);
    BIG_384_29_mod(hv,q);

    for (;;)
    {
        FP2_BLS381_from_BIGs(&X,one,hv);
        if (ECP2_BLS381_setx(Q,&X)) break;
        BIG_384_29_inc(hv,1);
    }

    BIG_384_29_rcopy(Fx,Fra_BLS381);
    BIG_384_29_rcopy(Fy,Frb_BLS381);
    FP2_BLS381_from_BIGs(&X,Fx,Fy);

#if SEXTIC_TWIST_BLS381==M_TYPE
    FP2_BLS381_inv(&X,&X);
    FP2_BLS381_norm(&X);
#endif

    BIG_384_29_rcopy(x,CURVE_Bnx_BLS381);

#if (PAIRING_FRIENDLY_BLS381 == BN)

    /* Faster Hashing to G2 - Fuentes-Castaneda, Knapp and Rodriguez-Henriquez */
    /* Q -> xQ + F(3xQ) + F(F(xQ)) + F(F(F(Q))). */
    ECP2_BLS381_copy(&T,Q);
    ECP2_BLS381_mul(&T,x);
#if SIGN_OF_X_BLS381==NEGATIVEX
    ECP2_BLS381_neg(&T);   // our x is negative
#endif
    ECP2_BLS381_copy(&K,&T);
    ECP2_BLS381_dbl(&K);
    ECP2_BLS381_add(&K,&T);
    //ECP2_BLS381_affine(&K);

    ECP2_BLS381_frob(&K,&X);
    ECP2_BLS381_frob(Q,&X);
    ECP2_BLS381_frob(Q,&X);
    ECP2_BLS381_frob(Q,&X);
    ECP2_BLS381_add(Q,&T);
    ECP2_BLS381_add(Q,&K);
    ECP2_BLS381_frob(&T,&X);
    ECP2_BLS381_frob(&T,&X);
    ECP2_BLS381_add(Q,&T);
    ECP2_BLS381_affine(Q);

#elif (PAIRING_FRIENDLY_BLS381 == BLS)

    /* Efficient hash maps to G2 on BLS curves - Budroni, Pintore */
    /* Q -> x2Q -xQ -Q +F(xQ -Q) +F(F(2Q)) */

    ECP2_BLS381_copy(&xQ,Q);
    ECP2_BLS381_mul(&xQ,x);

    ECP2_BLS381_copy(&x2Q,&xQ);
    ECP2_BLS381_mul(&x2Q,x);

#if SIGN_OF_X_BLS381==NEGATIVEX
    ECP2_BLS381_neg(&xQ);
#endif

    ECP2_BLS381_sub(&x2Q,&xQ);
    ECP2_BLS381_sub(&x2Q,Q);

    ECP2_BLS381_sub(&xQ,Q);
    ECP2_BLS381_frob(&xQ,&X);

    ECP2_BLS381_dbl(Q);
    ECP2_BLS381_frob(Q,&X);
    ECP2_BLS381_frob(Q,&X);

    ECP2_BLS381_add(Q,&x2Q);
    ECP2_BLS381_add(Q,&xQ);

    ECP2_BLS381_affine(Q);

#endif
}

void ECP2_BLS381_generator(ECP2_BLS381 *G)
{
	FP2_BLS381 wx,wy;

    FP_BLS381_rcopy(&(wx.a),CURVE_Pxa_BLS381); 
    FP_BLS381_rcopy(&(wx.b),CURVE_Pxb_BLS381); 
    FP_BLS381_rcopy(&(wy.a),CURVE_Pya_BLS381); 
    FP_BLS381_rcopy(&(wy.b),CURVE_Pyb_BLS381);     
	ECP2_BLS381_set(G,&wx,&wy);
}

/*

int main()
{
	int i;
	ECP2_BLS381 G,P;
	ECP2_BLS381 *W;
	FP2_BLS381 x,y,w,z,f;
	BIG_384_29 r,xa,xb,ya,yb;

	BIG_384_29_rcopy(xa,CURVE_Pxa_BLS381);
	BIG_384_29_rcopy(xb,CURVE_Pxb_BLS381);
	BIG_384_29_rcopy(ya,CURVE_Pya_BLS381);
	BIG_384_29_rcopy(yb,CURVE_Pyb_BLS381);

	FP2_BLS381_from_BIGs(&x,xa,xb);
	FP2_BLS381_from_BIGs(&y,ya,yb);
	ECP2_BLS381_set(&G,&x,&y);
	if (G.inf) printf("Failed to set - point not on curve\n");
	else printf("set success\n");

	ECP2_BLS381_output(&G);

//	BIG_384_29_copy(r,CURVE_Order_BLS381);
	BIG_384_29_rcopy(r,Modulus_BLS381);

	ECP2_BLS381_copy(&P,&G);

	ECP2_BLS381_mul(&P,r);

	ECP2_BLS381_output(&P);

	FP2_BLS381_gfc(&f,12);

	ECP2_BLS381_frob(&G,&f);

	ECP2_BLS381_output(&G);

	return 0;
}

*/
