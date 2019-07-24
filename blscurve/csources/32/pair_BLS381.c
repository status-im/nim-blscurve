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

/* AMCL BN Curve pairing functions */

//#define HAS_MAIN

#include "pair_BLS381.h"

/* Line function */
static void PAIR_BLS381_line(FP12_BLS381 *v,ECP2_BLS381 *A,ECP2_BLS381 *B,FP_BLS381 *Qx,FP_BLS381 *Qy)
{
    FP2_BLS381 X1,Y1,T1,T2;
    FP2_BLS381 XX,YY,ZZ,YZ;
    FP4_BLS381 a,b,c;

    if (A==B)
    {
        /* doubling */
        FP2_BLS381_copy(&XX,&(A->x));	//FP2 XX=new FP2(A.getx());  //X
        FP2_BLS381_copy(&YY,&(A->y));	//FP2 YY=new FP2(A.gety());  //Y
        FP2_BLS381_copy(&ZZ,&(A->z));	//FP2 ZZ=new FP2(A.getz());  //Z


        FP2_BLS381_copy(&YZ,&YY);		//FP2 YZ=new FP2(YY);        //Y
        FP2_BLS381_mul(&YZ,&YZ,&ZZ);		//YZ.mul(ZZ);                //YZ
        FP2_BLS381_sqr(&XX,&XX);		//XX.sqr();	               //X^2
        FP2_BLS381_sqr(&YY,&YY);		//YY.sqr();	               //Y^2
        FP2_BLS381_sqr(&ZZ,&ZZ);		//ZZ.sqr();			       //Z^2

        FP2_BLS381_imul(&YZ,&YZ,4);	//YZ.imul(4);
        FP2_BLS381_neg(&YZ,&YZ);		//YZ.neg();
        FP2_BLS381_norm(&YZ);			//YZ.norm();       //-4YZ

        FP2_BLS381_imul(&XX,&XX,6);					//6X^2
        FP2_BLS381_pmul(&XX,&XX,Qx);	               //6X^2.Xs

        FP2_BLS381_imul(&ZZ,&ZZ,3*CURVE_B_I_BLS381);	//3Bz^2

        FP2_BLS381_pmul(&YZ,&YZ,Qy);	//-4YZ.Ys

#if SEXTIC_TWIST_BLS381==D_TYPE
        FP2_BLS381_div_ip2(&ZZ);		//6(b/i)z^2
#endif
#if SEXTIC_TWIST_BLS381==M_TYPE
        FP2_BLS381_mul_ip(&ZZ);
        FP2_BLS381_add(&ZZ,&ZZ,&ZZ);  // 6biz^2
        FP2_BLS381_mul_ip(&YZ);
        FP2_BLS381_norm(&YZ);
#endif
        FP2_BLS381_norm(&ZZ);			// 6bi.Z^2

        FP2_BLS381_add(&YY,&YY,&YY);	// 2y^2
        FP2_BLS381_sub(&ZZ,&ZZ,&YY);	//
        FP2_BLS381_norm(&ZZ);			// 6b.Z^2-2Y^2

        FP4_BLS381_from_FP2s(&a,&YZ,&ZZ); // -4YZ.Ys | 6b.Z^2-2Y^2 | 6X^2.Xs
#if SEXTIC_TWIST_BLS381==D_TYPE
        FP4_BLS381_from_FP2(&b,&XX);
        FP4_BLS381_zero(&c);
#endif
#if SEXTIC_TWIST_BLS381==M_TYPE
        FP4_BLS381_zero(&b);
        FP4_BLS381_from_FP2H(&c,&XX);
#endif

        ECP2_BLS381_dbl(A);				//A.dbl();
    }
    else
    {
        /* addition */

        FP2_BLS381_copy(&X1,&(A->x));		//FP2 X1=new FP2(A.getx());    // X1
        FP2_BLS381_copy(&Y1,&(A->y));		//FP2 Y1=new FP2(A.gety());    // Y1
        FP2_BLS381_copy(&T1,&(A->z));		//FP2 T1=new FP2(A.getz());    // Z1

        FP2_BLS381_copy(&T2,&T1);		//FP2 T2=new FP2(A.getz());    // Z1

        FP2_BLS381_mul(&T1,&T1,&(B->y));	//T1.mul(B.gety());    // T1=Z1.Y2
        FP2_BLS381_mul(&T2,&T2,&(B->x));	//T2.mul(B.getx());    // T2=Z1.X2

        FP2_BLS381_sub(&X1,&X1,&T2);		//X1.sub(T2);
        FP2_BLS381_norm(&X1);				//X1.norm();  // X1=X1-Z1.X2
        FP2_BLS381_sub(&Y1,&Y1,&T1);		//Y1.sub(T1);
        FP2_BLS381_norm(&Y1);				//Y1.norm();  // Y1=Y1-Z1.Y2

        FP2_BLS381_copy(&T1,&X1);			//T1.copy(X1);            // T1=X1-Z1.X2

        FP2_BLS381_pmul(&X1,&X1,Qy);		//X1.pmul(Qy);            // X1=(X1-Z1.X2).Ys
#if SEXTIC_TWIST_BLS381==M_TYPE
        FP2_BLS381_mul_ip(&X1);
        FP2_BLS381_norm(&X1);
#endif

        FP2_BLS381_mul(&T1,&T1,&(B->y));	//T1.mul(B.gety());       // T1=(X1-Z1.X2).Y2

        FP2_BLS381_copy(&T2,&Y1);			//T2.copy(Y1);            // T2=Y1-Z1.Y2
        FP2_BLS381_mul(&T2,&T2,&(B->x));	//T2.mul(B.getx());       // T2=(Y1-Z1.Y2).X2
        FP2_BLS381_sub(&T2,&T2,&T1);		//T2.sub(T1);
        FP2_BLS381_norm(&T2);				//T2.norm();          // T2=(Y1-Z1.Y2).X2 - (X1-Z1.X2).Y2
        FP2_BLS381_pmul(&Y1,&Y1,Qx);		//Y1.pmul(Qx);
        FP2_BLS381_neg(&Y1,&Y1);			//Y1.neg();
        FP2_BLS381_norm(&Y1);				//Y1.norm(); // Y1=-(Y1-Z1.Y2).Xs

        FP4_BLS381_from_FP2s(&a,&X1,&T2);	// (X1-Z1.X2).Ys  |  (Y1-Z1.Y2).X2 - (X1-Z1.X2).Y2  | - (Y1-Z1.Y2).Xs
#if SEXTIC_TWIST_BLS381==D_TYPE
        FP4_BLS381_from_FP2(&b,&Y1);		//b=new FP4(Y1);
        FP4_BLS381_zero(&c);
#endif
#if SEXTIC_TWIST_BLS381==M_TYPE
        FP4_BLS381_zero(&b);
        FP4_BLS381_from_FP2H(&c,&Y1);		//b=new FP4(Y1);
#endif
        ECP2_BLS381_add(A,B);			//A.add(B);
    }

    FP12_BLS381_from_FP4s(v,&a,&b,&c);
    v->type=AMCL_FP_SPARSER;
}


/* prepare ate parameter, n=6u+2 (BN) or n=u (BLS), n3=3*n */
int PAIR_BLS381_nbits(BIG_384_29 n3,BIG_384_29 n)
{
    BIG_384_29 x;
    BIG_384_29_rcopy(x,CURVE_Bnx_BLS381);

#if PAIRING_FRIENDLY_BLS381==BN
    BIG_384_29_pmul(n,x,6);
#if SIGN_OF_X_BLS381==POSITIVEX
    BIG_384_29_inc(n,2);
#else
    BIG_384_29_dec(n,2);
#endif

#else
    BIG_384_29_copy(n,x);
#endif

    BIG_384_29_norm(n);
    BIG_384_29_pmul(n3,n,3);
    BIG_384_29_norm(n3);

    return BIG_384_29_nbits(n3);
}

/*
	For multi-pairing, product of n pairings
	1. Declare FP12 array of length number of bits in Ate parameter
	2. Initialise this array by calling PAIR_initmp()
	3. Accumulate each pairing by calling PAIR_another() n times
	4. Call PAIR_miller()
	5. Call final exponentiation PAIR_fexp()
*/

/* prepare for multi-pairing */
void PAIR_BLS381_initmp(FP12_BLS381 r[])
{
    int i;
    for (i=ATE_BITS_BLS381-1; i>=0; i--)
        FP12_BLS381_one(&r[i]);
    return;
}

/* basic Miller loop */
void PAIR_BLS381_miller(FP12_BLS381 *res,FP12_BLS381 r[])
{
    int i;
    FP12_BLS381_one(res);
    for (i=ATE_BITS_BLS381-1; i>=1; i--)
    {
        FP12_BLS381_sqr(res,res);
        FP12_BLS381_ssmul(res,&r[i]);
    }

#if SIGN_OF_X_BLS381==NEGATIVEX
    FP12_BLS381_conj(res,res);
#endif
    FP12_BLS381_ssmul(res,&r[0]);
    return;
}

/* Accumulate another set of line functions for n-pairing */
void PAIR_BLS381_another(FP12_BLS381 r[],ECP2_BLS381* PV,ECP_BLS381* QV)
{
    int i,nb,bt;
    BIG_384_29 n,n3;
    FP12_BLS381 lv,lv2;
    ECP2_BLS381 A,NP,P;
    ECP_BLS381 Q;
    FP_BLS381 Qx,Qy;
#if PAIRING_FRIENDLY_BLS381==BN
    ECP2_BLS381 K;
    FP2_BLS381 X;
    FP_BLS381_rcopy(&Qx,Fra_BLS381);
    FP_BLS381_rcopy(&Qy,Frb_BLS381);
    FP2_BLS381_from_FPs(&X,&Qx,&Qy);
#if SEXTIC_TWIST_BLS381==M_TYPE
    FP2_BLS381_inv(&X,&X);
    FP2_BLS381_norm(&X);
#endif
#endif

    nb=PAIR_BLS381_nbits(n3,n);

    ECP2_BLS381_copy(&P,PV);
    ECP_BLS381_copy(&Q,QV);

    ECP2_BLS381_affine(&P);
    ECP_BLS381_affine(&Q);

    FP_BLS381_copy(&Qx,&(Q.x));
    FP_BLS381_copy(&Qy,&(Q.y));

    ECP2_BLS381_copy(&A,&P);
    ECP2_BLS381_copy(&NP,&P);
    ECP2_BLS381_neg(&NP);

    for (i=nb-2; i>=1; i--)
    {
        PAIR_BLS381_line(&lv,&A,&A,&Qx,&Qy);

        bt=BIG_384_29_bit(n3,i)-BIG_384_29_bit(n,i); // bt=BIG_bit(n,i);
        if (bt==1)
        {
            PAIR_BLS381_line(&lv2,&A,&P,&Qx,&Qy);
            FP12_BLS381_smul(&lv,&lv2);
        }
        if (bt==-1)
        {
            PAIR_BLS381_line(&lv2,&A,&NP,&Qx,&Qy);
            FP12_BLS381_smul(&lv,&lv2);
        }
        FP12_BLS381_ssmul(&r[i],&lv);
    }

#if PAIRING_FRIENDLY_BLS381==BN

#if SIGN_OF_X_BLS381==NEGATIVEX
    ECP2_BLS381_neg(&A);
#endif

    ECP2_BLS381_copy(&K,&P);
    ECP2_BLS381_frob(&K,&X);
    PAIR_BLS381_line(&lv,&A,&K,&Qx,&Qy);
    ECP2_BLS381_frob(&K,&X);
    ECP2_BLS381_neg(&K);
    PAIR_BLS381_line(&lv2,&A,&K,&Qx,&Qy);
    FP12_BLS381_smul(&lv,&lv2);
    FP12_BLS381_ssmul(&r[0],&lv);

#endif
}

/* Optimal R-ate pairing r=e(P,Q) */
void PAIR_BLS381_ate(FP12_BLS381 *r,ECP2_BLS381 *P1,ECP_BLS381 *Q1)
{
    BIG_384_29 n,n3;
    FP_BLS381 Qx,Qy;
    int i,nb,bt;
    ECP2_BLS381 A,NP,P;
    ECP_BLS381 Q;
    FP12_BLS381 lv,lv2;
#if PAIRING_FRIENDLY_BLS381==BN
    ECP2_BLS381 KA;
    FP2_BLS381 X;

    FP_BLS381_rcopy(&Qx,Fra_BLS381);
    FP_BLS381_rcopy(&Qy,Frb_BLS381);
    FP2_BLS381_from_FPs(&X,&Qx,&Qy);

#if SEXTIC_TWIST_BLS381==M_TYPE
    FP2_BLS381_inv(&X,&X);
    FP2_BLS381_norm(&X);
#endif
#endif

    nb=PAIR_BLS381_nbits(n3,n);

    ECP2_BLS381_copy(&P,P1);
    ECP_BLS381_copy(&Q,Q1);

    ECP2_BLS381_affine(&P);
    ECP_BLS381_affine(&Q);

    FP_BLS381_copy(&Qx,&(Q.x));
    FP_BLS381_copy(&Qy,&(Q.y));

    ECP2_BLS381_copy(&A,&P);
    ECP2_BLS381_copy(&NP,&P);
    ECP2_BLS381_neg(&NP);

    FP12_BLS381_one(r);

    /* Main Miller Loop */
    for (i=nb-2; i>=1; i--)   //0
    {
        FP12_BLS381_sqr(r,r);
        PAIR_BLS381_line(&lv,&A,&A,&Qx,&Qy);

        bt=BIG_384_29_bit(n3,i)-BIG_384_29_bit(n,i); // bt=BIG_bit(n,i);
        if (bt==1)
        {
            PAIR_BLS381_line(&lv2,&A,&P,&Qx,&Qy);
            FP12_BLS381_smul(&lv,&lv2);
        }
        if (bt==-1)
        {
            PAIR_BLS381_line(&lv2,&A,&NP,&Qx,&Qy);
            FP12_BLS381_smul(&lv,&lv2);
        }
        FP12_BLS381_ssmul(r,&lv);

    }


#if SIGN_OF_X_BLS381==NEGATIVEX
    FP12_BLS381_conj(r,r);
#endif

    /* R-ate fixup required for BN curves */
#if PAIRING_FRIENDLY_BLS381==BN

#if SIGN_OF_X_BLS381==NEGATIVEX
    ECP2_BLS381_neg(&A);
#endif

    ECP2_BLS381_copy(&KA,&P);
    ECP2_BLS381_frob(&KA,&X);
    PAIR_BLS381_line(&lv,&A,&KA,&Qx,&Qy);
    ECP2_BLS381_frob(&KA,&X);
    ECP2_BLS381_neg(&KA);
    PAIR_BLS381_line(&lv2,&A,&KA,&Qx,&Qy);
    FP12_BLS381_smul(&lv,&lv2);
    FP12_BLS381_ssmul(r,&lv);
#endif
}

/* Optimal R-ate double pairing e(P,Q).e(R,S) */
void PAIR_BLS381_double_ate(FP12_BLS381 *r,ECP2_BLS381 *P1,ECP_BLS381 *Q1,ECP2_BLS381 *R1,ECP_BLS381 *S1)
{
    BIG_384_29 n,n3;
    FP_BLS381 Qx,Qy,Sx,Sy;
    int i,nb,bt;
    ECP2_BLS381 A,B,NP,NR,P,R;
    ECP_BLS381 Q,S;
    FP12_BLS381 lv,lv2;
#if PAIRING_FRIENDLY_BLS381==BN
    FP2_BLS381 X;
    ECP2_BLS381 K;

    FP_BLS381_rcopy(&Qx,Fra_BLS381);
    FP_BLS381_rcopy(&Qy,Frb_BLS381);
    FP2_BLS381_from_FPs(&X,&Qx,&Qy);

#if SEXTIC_TWIST_BLS381==M_TYPE
    FP2_BLS381_inv(&X,&X);
    FP2_BLS381_norm(&X);
#endif
#endif
    nb=PAIR_BLS381_nbits(n3,n);

    ECP2_BLS381_copy(&P,P1);
    ECP_BLS381_copy(&Q,Q1);

    ECP2_BLS381_affine(&P);
    ECP_BLS381_affine(&Q);

    ECP2_BLS381_copy(&R,R1);
    ECP_BLS381_copy(&S,S1);

    ECP2_BLS381_affine(&R);
    ECP_BLS381_affine(&S);

    FP_BLS381_copy(&Qx,&(Q.x));
    FP_BLS381_copy(&Qy,&(Q.y));

    FP_BLS381_copy(&Sx,&(S.x));
    FP_BLS381_copy(&Sy,&(S.y));

    ECP2_BLS381_copy(&A,&P);
    ECP2_BLS381_copy(&B,&R);

    ECP2_BLS381_copy(&NP,&P);
    ECP2_BLS381_neg(&NP);
    ECP2_BLS381_copy(&NR,&R);
    ECP2_BLS381_neg(&NR);

    FP12_BLS381_one(r);

    /* Main Miller Loop */
    for (i=nb-2; i>=1; i--)
    {
        FP12_BLS381_sqr(r,r);
        PAIR_BLS381_line(&lv,&A,&A,&Qx,&Qy);
        PAIR_BLS381_line(&lv2,&B,&B,&Sx,&Sy);
        FP12_BLS381_smul(&lv,&lv2);
        FP12_BLS381_ssmul(r,&lv);

        bt=BIG_384_29_bit(n3,i)-BIG_384_29_bit(n,i); // bt=BIG_bit(n,i);
        if (bt==1)
        {
            PAIR_BLS381_line(&lv,&A,&P,&Qx,&Qy);
            PAIR_BLS381_line(&lv2,&B,&R,&Sx,&Sy);
            FP12_BLS381_smul(&lv,&lv2);
            FP12_BLS381_ssmul(r,&lv);
        }
        if (bt==-1)
        {
            PAIR_BLS381_line(&lv,&A,&NP,&Qx,&Qy);
            PAIR_BLS381_line(&lv2,&B,&NR,&Sx,&Sy);
            FP12_BLS381_smul(&lv,&lv2);
            FP12_BLS381_ssmul(r,&lv);
        }

    }


    /* R-ate fixup required for BN curves */

#if SIGN_OF_X_BLS381==NEGATIVEX
    FP12_BLS381_conj(r,r);
#endif

#if PAIRING_FRIENDLY_BLS381==BN

#if SIGN_OF_X_BLS381==NEGATIVEX
    ECP2_BLS381_neg(&A);
    ECP2_BLS381_neg(&B);
#endif

    ECP2_BLS381_copy(&K,&P);
    ECP2_BLS381_frob(&K,&X);
    PAIR_BLS381_line(&lv,&A,&K,&Qx,&Qy);
    ECP2_BLS381_frob(&K,&X);
    ECP2_BLS381_neg(&K);
    PAIR_BLS381_line(&lv2,&A,&K,&Qx,&Qy);
    FP12_BLS381_smul(&lv,&lv2);
    FP12_BLS381_ssmul(r,&lv);

    ECP2_BLS381_copy(&K,&R);
    ECP2_BLS381_frob(&K,&X);
    PAIR_BLS381_line(&lv,&B,&K,&Sx,&Sy);
    ECP2_BLS381_frob(&K,&X);
    ECP2_BLS381_neg(&K);
    PAIR_BLS381_line(&lv2,&B,&K,&Sx,&Sy);
    FP12_BLS381_smul(&lv,&lv2);
    FP12_BLS381_ssmul(r,&lv);
#endif
}

/* final exponentiation - keep separate for multi-pairings and to avoid thrashing stack */
void PAIR_BLS381_fexp(FP12_BLS381 *r)
{
    FP2_BLS381 X;
    BIG_384_29 x;
    FP_BLS381 a,b;
    FP12_BLS381 t0,y0,y1,y2,y3;

    BIG_384_29_rcopy(x,CURVE_Bnx_BLS381);
    FP_BLS381_rcopy(&a,Fra_BLS381);
    FP_BLS381_rcopy(&b,Frb_BLS381);
    FP2_BLS381_from_FPs(&X,&a,&b);

    /* Easy part of final exp */

    FP12_BLS381_inv(&t0,r);
    FP12_BLS381_conj(r,r);

    FP12_BLS381_mul(r,&t0);
    FP12_BLS381_copy(&t0,r);

    FP12_BLS381_frob(r,&X);
    FP12_BLS381_frob(r,&X);
    FP12_BLS381_mul(r,&t0);

//    if (FP12_BLS381_isunity(r))
//    {
//        FP12_BLS381_zero(r);
//        return;
//    }

    /* Hard part of final exp - see Duquesne & Ghamman eprint 2015/192.pdf */
#if PAIRING_FRIENDLY_BLS381==BN
    FP12_BLS381_pow(&t0,r,x); // t0=f^-u
#if SIGN_OF_X_BLS381==POSITIVEX
    FP12_BLS381_conj(&t0,&t0);
#endif
    FP12_BLS381_usqr(&y3,&t0); // y3=t0^2
    FP12_BLS381_copy(&y0,&t0);
    FP12_BLS381_mul(&y0,&y3); // y0=t0*y3
    FP12_BLS381_copy(&y2,&y3);
    FP12_BLS381_frob(&y2,&X); // y2=y3^p
    FP12_BLS381_mul(&y2,&y3); //y2=y2*y3
    FP12_BLS381_usqr(&y2,&y2); //y2=y2^2
    FP12_BLS381_mul(&y2,&y3); // y2=y2*y3

    FP12_BLS381_pow(&t0,&y0,x);  //t0=y0^-u
#if SIGN_OF_X_BLS381==POSITIVEX
    FP12_BLS381_conj(&t0,&t0);
#endif
    FP12_BLS381_conj(&y0,r);     //y0=~r
    FP12_BLS381_copy(&y1,&t0);
    FP12_BLS381_frob(&y1,&X);
    FP12_BLS381_frob(&y1,&X); //y1=t0^p^2
    FP12_BLS381_mul(&y1,&y0); // y1=y0*y1
    FP12_BLS381_conj(&t0,&t0); // t0=~t0
    FP12_BLS381_copy(&y3,&t0);
    FP12_BLS381_frob(&y3,&X); //y3=t0^p
    FP12_BLS381_mul(&y3,&t0); // y3=t0*y3
    FP12_BLS381_usqr(&t0,&t0); // t0=t0^2
    FP12_BLS381_mul(&y1,&t0); // y1=t0*y1

    FP12_BLS381_pow(&t0,&y3,x); // t0=y3^-u
#if SIGN_OF_X_BLS381==POSITIVEX
    FP12_BLS381_conj(&t0,&t0);
#endif
    FP12_BLS381_usqr(&t0,&t0); //t0=t0^2
    FP12_BLS381_conj(&t0,&t0); //t0=~t0
    FP12_BLS381_mul(&y3,&t0); // y3=t0*y3

    FP12_BLS381_frob(r,&X);
    FP12_BLS381_copy(&y0,r);
    FP12_BLS381_frob(r,&X);
    FP12_BLS381_mul(&y0,r);
    FP12_BLS381_frob(r,&X);
    FP12_BLS381_mul(&y0,r);

    FP12_BLS381_usqr(r,&y3);  //r=y3^2
    FP12_BLS381_mul(r,&y2);   //r=y2*r
    FP12_BLS381_copy(&y3,r);
    FP12_BLS381_mul(&y3,&y0); // y3=r*y0
    FP12_BLS381_mul(r,&y1); // r=r*y1
    FP12_BLS381_usqr(r,r); // r=r^2
    FP12_BLS381_mul(r,&y3); // r=r*y3
    FP12_BLS381_reduce(r);
#else
// Ghamman & Fouotsa Method

    FP12_BLS381_usqr(&y0,r);
    FP12_BLS381_pow(&y1,&y0,x);
#if SIGN_OF_X_BLS381==NEGATIVEX
    FP12_BLS381_conj(&y1,&y1);
#endif


    BIG_384_29_fshr(x,1);
    FP12_BLS381_pow(&y2,&y1,x);
#if SIGN_OF_X_BLS381==NEGATIVEX
    FP12_BLS381_conj(&y2,&y2);
#endif


    BIG_384_29_fshl(x,1); // x must be even
    FP12_BLS381_conj(&y3,r);
    FP12_BLS381_mul(&y1,&y3);

    FP12_BLS381_conj(&y1,&y1);
    FP12_BLS381_mul(&y1,&y2);

    FP12_BLS381_pow(&y2,&y1,x);
#if SIGN_OF_X_BLS381==NEGATIVEX
    FP12_BLS381_conj(&y2,&y2);
#endif

    FP12_BLS381_pow(&y3,&y2,x);
#if SIGN_OF_X_BLS381==NEGATIVEX
    FP12_BLS381_conj(&y3,&y3);
#endif
    FP12_BLS381_conj(&y1,&y1);
    FP12_BLS381_mul(&y3,&y1);

    FP12_BLS381_conj(&y1,&y1);
    FP12_BLS381_frob(&y1,&X);
    FP12_BLS381_frob(&y1,&X);
    FP12_BLS381_frob(&y1,&X);
    FP12_BLS381_frob(&y2,&X);
    FP12_BLS381_frob(&y2,&X);
    FP12_BLS381_mul(&y1,&y2);

    FP12_BLS381_pow(&y2,&y3,x);
#if SIGN_OF_X_BLS381==NEGATIVEX
    FP12_BLS381_conj(&y2,&y2);
#endif
    FP12_BLS381_mul(&y2,&y0);
    FP12_BLS381_mul(&y2,r);

    FP12_BLS381_mul(&y1,&y2);
    FP12_BLS381_copy(&y2,&y3);
    FP12_BLS381_frob(&y2,&X);
    FP12_BLS381_mul(&y1,&y2);
    FP12_BLS381_copy(r,&y1);
    FP12_BLS381_reduce(r);

#endif
}

#ifdef USE_GLV_BLS381
/* GLV method */
static void glv(BIG_384_29 u[2],BIG_384_29 e)
{
#if PAIRING_FRIENDLY_BLS381==BN
    int i,j;
    BIG_384_29 v[2],t,q;
    DBIG_384_29 d;
    BIG_384_29_rcopy(q,CURVE_Order_BLS381);
    for (i=0; i<2; i++)
    {
        BIG_384_29_rcopy(t,CURVE_W_BLS381[i]);
        BIG_384_29_mul(d,t,e);
        BIG_384_29_ddiv(v[i],d,q);
        BIG_384_29_zero(u[i]);
    }
    BIG_384_29_copy(u[0],e);
    for (i=0; i<2; i++)
        for (j=0; j<2; j++)
        {
            BIG_384_29_rcopy(t,CURVE_SB_BLS381[j][i]);
            BIG_384_29_modmul(t,v[j],t,q);
            BIG_384_29_add(u[i],u[i],q);
            BIG_384_29_sub(u[i],u[i],t);
            BIG_384_29_mod(u[i],q);
        }

#else
// -(x^2).P = (Beta.x,y)

    BIG_384_29 x,x2,q;
    BIG_384_29_rcopy(x,CURVE_Bnx_BLS381);
    BIG_384_29_smul(x2,x,x);
    BIG_384_29_copy(u[0],e);
    BIG_384_29_mod(u[0],x2);
    BIG_384_29_copy(u[1],e);
    BIG_384_29_sdiv(u[1],x2);

    BIG_384_29_rcopy(q,CURVE_Order_BLS381);
    BIG_384_29_sub(u[1],q,u[1]);

#endif

    return;
}
#endif // USE_GLV

/* Galbraith & Scott Method */
static void gs(BIG_384_29 u[4],BIG_384_29 e)
{
    int i;
#if PAIRING_FRIENDLY_BLS381==BN
    int j;
    BIG_384_29 v[4],t,q;
    DBIG_384_29 d;
    BIG_384_29_rcopy(q,CURVE_Order_BLS381);
    for (i=0; i<4; i++)
    {
        BIG_384_29_rcopy(t,CURVE_WB_BLS381[i]);
        BIG_384_29_mul(d,t,e);
        BIG_384_29_ddiv(v[i],d,q);
        BIG_384_29_zero(u[i]);
    }

    BIG_384_29_copy(u[0],e);
    for (i=0; i<4; i++)
        for (j=0; j<4; j++)
        {
            BIG_384_29_rcopy(t,CURVE_BB_BLS381[j][i]);
            BIG_384_29_modmul(t,v[j],t,q);
            BIG_384_29_add(u[i],u[i],q);
            BIG_384_29_sub(u[i],u[i],t);
            BIG_384_29_mod(u[i],q);
        }

#else

    BIG_384_29 x,w,q;
    BIG_384_29_rcopy(q,CURVE_Order_BLS381);
    BIG_384_29_rcopy(x,CURVE_Bnx_BLS381);
    BIG_384_29_copy(w,e);

    for (i=0; i<3; i++)
    {
        BIG_384_29_copy(u[i],w);
        BIG_384_29_mod(u[i],x);
        BIG_384_29_sdiv(w,x);
    }
    BIG_384_29_copy(u[3],w);

    /*  */
#if SIGN_OF_X_BLS381==NEGATIVEX
    BIG_384_29_modneg(u[1],u[1],q);
    BIG_384_29_modneg(u[3],u[3],q);
#endif

#endif



    return;
}

/* Multiply P by e in group G1 */
void PAIR_BLS381_G1mul(ECP_BLS381 *P,BIG_384_29 e)
{
#ifdef USE_GLV_BLS381   /* Note this method is patented */
    int np,nn;
    ECP_BLS381 Q;
    FP_BLS381 cru;
    BIG_384_29 t,q;
    BIG_384_29 u[2];

    BIG_384_29_rcopy(q,CURVE_Order_BLS381);
    glv(u,e);

    ECP_BLS381_copy(&Q,P);
    ECP_BLS381_affine(&Q);
    FP_BLS381_rcopy(&cru,CURVE_Cru_BLS381);
    FP_BLS381_mul(&(Q.x),&(Q.x),&cru);

    /* note that -a.B = a.(-B). Use a or -a depending on which is smaller */

    np=BIG_384_29_nbits(u[0]);
    BIG_384_29_modneg(t,u[0],q);
    nn=BIG_384_29_nbits(t);
    if (nn<np)
    {
        BIG_384_29_copy(u[0],t);
        ECP_BLS381_neg(P);
    }

    np=BIG_384_29_nbits(u[1]);
    BIG_384_29_modneg(t,u[1],q);
    nn=BIG_384_29_nbits(t);
    if (nn<np)
    {
        BIG_384_29_copy(u[1],t);
        ECP_BLS381_neg(&Q);
    }
    BIG_384_29_norm(u[0]);
    BIG_384_29_norm(u[1]);
    ECP_BLS381_mul2(P,&Q,u[0],u[1]);

#else
    ECP_BLS381_mul(P,e);
#endif
}

/* Multiply P by e in group G2 */
void PAIR_BLS381_G2mul(ECP2_BLS381 *P,BIG_384_29 e)
{
#ifdef USE_GS_G2_BLS381   /* Well I didn't patent it :) */
    int i,np,nn;
    ECP2_BLS381 Q[4];
    FP2_BLS381 X;
    FP_BLS381 fx,fy;
    BIG_384_29 x,y,u[4];

    FP_BLS381_rcopy(&fx,Fra_BLS381);
    FP_BLS381_rcopy(&fy,Frb_BLS381);
    FP2_BLS381_from_FPs(&X,&fx,&fy);

#if SEXTIC_TWIST_BLS381==M_TYPE
    FP2_BLS381_inv(&X,&X);
    FP2_BLS381_norm(&X);
#endif

    BIG_384_29_rcopy(y,CURVE_Order_BLS381);
    gs(u,e);

    ECP2_BLS381_copy(&Q[0],P);
    for (i=1; i<4; i++)
    {
        ECP2_BLS381_copy(&Q[i],&Q[i-1]);
        ECP2_BLS381_frob(&Q[i],&X);
    }

    for (i=0; i<4; i++)
    {
        np=BIG_384_29_nbits(u[i]);
        BIG_384_29_modneg(x,u[i],y);
        nn=BIG_384_29_nbits(x);
        if (nn<np)
        {
            BIG_384_29_copy(u[i],x);
            ECP2_BLS381_neg(&Q[i]);
        }
        BIG_384_29_norm(u[i]);
    }

    ECP2_BLS381_mul4(P,Q,u);

#else
    ECP2_BLS381_mul(P,e);
#endif
}

/* f=f^e */
void PAIR_BLS381_GTpow(FP12_BLS381 *f,BIG_384_29 e)
{
#ifdef USE_GS_GT_BLS381   /* Note that this option requires a lot of RAM! Maybe better to use compressed XTR method, see fp4.c */
    int i,np,nn;
    FP12_BLS381 g[4];
    FP2_BLS381 X;
    BIG_384_29 t,q;
    FP_BLS381 fx,fy;
    BIG_384_29 u[4];

    FP_BLS381_rcopy(&fx,Fra_BLS381);
    FP_BLS381_rcopy(&fy,Frb_BLS381);
    FP2_BLS381_from_FPs(&X,&fx,&fy);

    BIG_384_29_rcopy(q,CURVE_Order_BLS381);
    gs(u,e);

    FP12_BLS381_copy(&g[0],f);
    for (i=1; i<4; i++)
    {
        FP12_BLS381_copy(&g[i],&g[i-1]);
        FP12_BLS381_frob(&g[i],&X);
    }

    for (i=0; i<4; i++)
    {
        np=BIG_384_29_nbits(u[i]);
        BIG_384_29_modneg(t,u[i],q);
        nn=BIG_384_29_nbits(t);
        if (nn<np)
        {
            BIG_384_29_copy(u[i],t);
            FP12_BLS381_conj(&g[i],&g[i]);
        }
        BIG_384_29_norm(u[i]);
    }
    FP12_BLS381_pow4(f,g,u);

#else
    FP12_BLS381_pow(f,f,e);
#endif
}


#ifdef HAS_MAIN

int main()
{
    int i;
    char byt[32];
    csprng rng;
    BIG_384_29 xa,xb,ya,yb,w,a,b,t1,q,u[2],v[4],m,r;
    ECP2_BLS381 P,G;
    ECP_BLS381 Q,R;
    FP12_BLS381 g,gp;
    FP4_BLS381 t,c,cp,cpm1,cpm2;
    FP2_BLS381 x,y,X;


    BIG_384_29_rcopy(a,CURVE_Fra);
    BIG_384_29_rcopy(b,CURVE_Frb);
    FP2_BLS381_from_BIGs(&X,a,b);

    BIG_384_29_rcopy(xa,CURVE_Gx);
    BIG_384_29_rcopy(ya,CURVE_Gy);

    ECP_BLS381_set(&Q,xa,ya);
    if (Q.inf) printf("Failed to set - point not on curve\n");
    else printf("G1 set success\n");

    printf("Q= ");
    ECP_BLS381_output(&Q);
    printf("\n");

    BIG_384_29_rcopy(xa,CURVE_Pxa);
    BIG_384_29_rcopy(xb,CURVE_Pxb);
    BIG_384_29_rcopy(ya,CURVE_Pya);
    BIG_384_29_rcopy(yb,CURVE_Pyb);

    FP2_BLS381_from_BIGs(&x,xa,xb);
    FP2_BLS381_from_BIGs(&y,ya,yb);

    ECP2_BLS381_set(&P,&x,&y);
    if (P.inf) printf("Failed to set - point not on curve\n");
    else printf("G2 set success\n");

    printf("P= ");
    ECP2_BLS381_output(&P);
    printf("\n");

    for (i=0; i<1000; i++ )
    {
        PAIR_BLS381_ate(&g,&P,&Q);
        PAIR_BLS381_fexp(&g);
    }
    printf("g= ");
    FP12_BLS381_output(&g);
    printf("\n");
}

#endif
