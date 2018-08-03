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

/* ECDH/ECIES/ECDSA Functions - see main program below */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "ecdh_BLS381.h"

/* Calculate a public/private EC GF(p) key pair. W=S.G mod EC(p),
 * where S is the secret key and W is the public key
 * and G is fixed generator.
 * If RNG is NULL then the private key is provided externally in S
 * otherwise it is generated randomly internally */
int ECP_BLS381_KEY_PAIR_GENERATE(csprng *RNG,octet* S,octet *W)
{
    BIG_384_29 r,gx,gy,s;
    ECP_BLS381 G;
    int res=0;

	ECP_BLS381_generator(&G);

    BIG_384_29_rcopy(r,CURVE_Order_BLS381);
    if (RNG!=NULL)
    {
        BIG_384_29_randomnum(s,r,RNG);
    }
    else
    {
        BIG_384_29_fromBytes(s,S->val);
        BIG_384_29_mod(s,r);
    }

#ifdef AES_S
    BIG_384_29_mod2m(s,2*AES_S);
//	BIG_toBytes(S->val,s);
#endif

    S->len=EGS_BLS381;
    BIG_384_29_toBytes(S->val,s);

    ECP_BLS381_mul(&G,s);

	ECP_BLS381_toOctet(W,&G,false);  /* To use point compression on public keys, change to true */
/*
#if CURVETYPE_BLS381!=MONTGOMERY
    ECP_BLS381_get(gx,gy,&G);
#else
    ECP_BLS381_get(gx,&G);

#endif



#if CURVETYPE_BLS381!=MONTGOMERY
    W->len=2*EFS_BLS381+1;
    W->val[0]=4;
    BIG_384_29_toBytes(&(W->val[1]),gx);
    BIG_384_29_toBytes(&(W->val[EFS_BLS381+1]),gy);
#else
    W->len=EFS_BLS381+1;
    W->val[0]=2;
    BIG_384_29_toBytes(&(W->val[1]),gx);
#endif
*/
    return res;
}

/* Validate public key */
int ECP_BLS381_PUBLIC_KEY_VALIDATE(octet *W)
{
    BIG_384_29 q,r,wx,k;
    ECP_BLS381 WP;
    int valid,nb;
    int res=0;

    BIG_384_29_rcopy(q,Modulus_BLS381);
    BIG_384_29_rcopy(r,CURVE_Order_BLS381);

	valid=ECP_BLS381_fromOctet(&WP,W);
	if (!valid) res=ECDH_INVALID_PUBLIC_KEY;

/*
    BIG_384_29_fromBytes(wx,&(W->val[1]));
    if (BIG_384_29_comp(wx,q)>=0) res=ECDH_INVALID_PUBLIC_KEY;
#if CURVETYPE_BLS381!=MONTGOMERY
    BIG_384_29 wy;
    BIG_384_29_fromBytes(wy,&(W->val[EFS_BLS381+1]));
    if (BIG_384_29_comp(wy,q)>=0) res=ECDH_INVALID_PUBLIC_KEY;
#endif
*/
    if (res==0)
    {

//#if CURVETYPE_BLS381!=MONTGOMERY
//        valid=ECP_BLS381_set(&WP,wx,wy);
//#else
//        valid=ECP_BLS381_set(&WP,wx);
//#endif
//        if (!valid || ECP_BLS381_isinf(&WP)) res=ECDH_INVALID_PUBLIC_KEY;
//        if (res==0 )
//        {
            /* Check point is not in wrong group */
            nb=BIG_384_29_nbits(q);
            BIG_384_29_one(k);
            BIG_384_29_shl(k,(nb+4)/2);
            BIG_384_29_add(k,q,k);
            BIG_384_29_sdiv(k,r); /* get co-factor */

            while (BIG_384_29_parity(k)==0)
            {
                ECP_BLS381_dbl(&WP);
                BIG_384_29_fshr(k,1);
            }

            if (!BIG_384_29_isunity(k)) ECP_BLS381_mul(&WP,k);
            if (ECP_BLS381_isinf(&WP)) res=ECDH_INVALID_PUBLIC_KEY;
//        }
    }

    return res;
}

/* IEEE-1363 Diffie-Hellman online calculation Z=S.WD */
int ECP_BLS381_SVDP_DH(octet *S,octet *WD,octet *Z)
{
    BIG_384_29 r,s,wx;
    int valid;
    ECP_BLS381 W;
    int res=0;

    BIG_384_29_fromBytes(s,S->val);

	valid=ECP_BLS381_fromOctet(&W,WD);
/*
    BIG_384_29_fromBytes(wx,&(WD->val[1]));
#if CURVETYPE_BLS381!=MONTGOMERY
    BIG_384_29 wy;
    BIG_384_29_fromBytes(wy,&(WD->val[EFS_BLS381+1]));
    valid=ECP_BLS381_set(&W,wx,wy);
#else
    valid=ECP_BLS381_set(&W,wx);
#endif
*/
    if (!valid) res=ECDH_ERROR;
    if (res==0)
    {
        BIG_384_29_rcopy(r,CURVE_Order_BLS381);
        BIG_384_29_mod(s,r);

        ECP_BLS381_mul(&W,s);
        if (ECP_BLS381_isinf(&W)) res=ECDH_ERROR;
        else
        {
#if CURVETYPE_BLS381!=MONTGOMERY
            ECP_BLS381_get(wx,wx,&W);
#else
            ECP_BLS381_get(wx,&W);
#endif
            Z->len=MODBYTES_384_29;
            BIG_384_29_toBytes(Z->val,wx);
        }
    }
    return res;
}

#if CURVETYPE_BLS381!=MONTGOMERY

/* IEEE ECDSA Signature, C and D are signature on F using private key S */
int ECP_BLS381_SP_DSA(int sha,csprng *RNG,octet *K,octet *S,octet *F,octet *C,octet *D)
{
    char h[128];
    octet H= {0,sizeof(h),h};

    BIG_384_29 gx,gy,r,s,f,c,d,u,vx,w;
    ECP_BLS381 G,V;

    ehashit(sha,F,-1,NULL,&H,sha);

	ECP_BLS381_generator(&G);

    BIG_384_29_rcopy(r,CURVE_Order_BLS381);

    BIG_384_29_fromBytes(s,S->val);

    int hlen=H.len;
    if (H.len>MODBYTES_384_29) hlen=MODBYTES_384_29;
    BIG_384_29_fromBytesLen(f,H.val,hlen);

	if (RNG!=NULL)
	{
		do
		{
       
            BIG_384_29_randomnum(u,r,RNG);
            BIG_384_29_randomnum(w,r,RNG); /* side channel masking */

#ifdef AES_S
			BIG_384_29_mod2m(u,2*AES_S);
#endif
			ECP_BLS381_copy(&V,&G);
			ECP_BLS381_mul(&V,u);

			ECP_BLS381_get(vx,vx,&V);

			BIG_384_29_copy(c,vx);
			BIG_384_29_mod(c,r);
			if (BIG_384_29_iszilch(c)) continue;
			
            BIG_384_29_modmul(u,u,w,r);

			BIG_384_29_invmodp(u,u,r);
			BIG_384_29_modmul(d,s,c,r);

			BIG_384_29_add(d,f,d);
			
            BIG_384_29_modmul(d,d,w,r);

			BIG_384_29_modmul(d,u,d,r);
		} while (BIG_384_29_iszilch(d));
	}
	else
	{
		BIG_384_29_fromBytes(u,K->val);
		BIG_384_29_mod(u,r);

#ifdef AES_S
        BIG_384_29_mod2m(u,2*AES_S);
#endif
        ECP_BLS381_copy(&V,&G);
        ECP_BLS381_mul(&V,u);

        ECP_BLS381_get(vx,vx,&V);

        BIG_384_29_copy(c,vx);
        BIG_384_29_mod(c,r);
        if (BIG_384_29_iszilch(c)) return ECDH_ERROR;
 

        BIG_384_29_invmodp(u,u,r);
        BIG_384_29_modmul(d,s,c,r);

        BIG_384_29_add(d,f,d);

        BIG_384_29_modmul(d,u,d,r);
        if (BIG_384_29_iszilch(d)) return ECDH_ERROR;
    }

    C->len=D->len=EGS_BLS381;

    BIG_384_29_toBytes(C->val,c);
    BIG_384_29_toBytes(D->val,d);

    return 0;
}

/* IEEE1363 ECDSA Signature Verification. Signature C and D on F is verified using public key W */
int ECP_BLS381_VP_DSA(int sha,octet *W,octet *F, octet *C,octet *D)
{
    char h[128];
    octet H= {0,sizeof(h),h};

    BIG_384_29 r,gx,gy,wx,wy,f,c,d,h2;
    int res=0;
    ECP_BLS381 G,WP;
    int valid;

    ehashit(sha,F,-1,NULL,&H,sha);

	ECP_BLS381_generator(&G);

    BIG_384_29_rcopy(r,CURVE_Order_BLS381);

    OCT_shl(C,C->len-MODBYTES_384_29);
    OCT_shl(D,D->len-MODBYTES_384_29);

    BIG_384_29_fromBytes(c,C->val);
    BIG_384_29_fromBytes(d,D->val);

    int hlen=H.len;
    if (hlen>MODBYTES_384_29) hlen=MODBYTES_384_29;

    BIG_384_29_fromBytesLen(f,H.val,hlen);

    //BIG_fromBytes(f,H.val);

    if (BIG_384_29_iszilch(c) || BIG_384_29_comp(c,r)>=0 || BIG_384_29_iszilch(d) || BIG_384_29_comp(d,r)>=0)
        res=ECDH_INVALID;

    if (res==0)
    {
        BIG_384_29_invmodp(d,d,r);
        BIG_384_29_modmul(f,f,d,r);
        BIG_384_29_modmul(h2,c,d,r);

		valid=ECP_BLS381_fromOctet(&WP,W);
/*
        BIG_384_29_fromBytes(wx,&(W->val[1]));
        BIG_384_29_fromBytes(wy,&(W->val[EFS_BLS381+1]));

        valid=ECP_BLS381_set(&WP,wx,wy);
*/
        if (!valid) res=ECDH_ERROR;
        else
        {
            ECP_BLS381_mul2(&WP,&G,h2,f);

            if (ECP_BLS381_isinf(&WP)) res=ECDH_INVALID;
            else
            {
                ECP_BLS381_get(d,d,&WP);
                BIG_384_29_mod(d,r);
                if (BIG_384_29_comp(d,c)!=0) res=ECDH_INVALID;
            }
        }
    }

    return res;
}

/* IEEE1363 ECIES encryption. Encryption of plaintext M uses public key W and produces ciphertext V,C,T */
void ECP_BLS381_ECIES_ENCRYPT(int sha,octet *P1,octet *P2,csprng *RNG,octet *W,octet *M,int tlen,octet *V,octet *C,octet *T)
{

    int i,len;
    char z[EFS_BLS381],vz[3*EFS_BLS381+1],k[2*AESKEY_BLS381],k1[AESKEY_BLS381],k2[AESKEY_BLS381],l2[8],u[EFS_BLS381];
    octet Z= {0,sizeof(z),z};
    octet VZ= {0,sizeof(vz),vz};
    octet K= {0,sizeof(k),k};
    octet K1= {0,sizeof(k1),k1};
    octet K2= {0,sizeof(k2),k2};
    octet L2= {0,sizeof(l2),l2};
    octet U= {0,sizeof(u),u};

    if (ECP_BLS381_KEY_PAIR_GENERATE(RNG,&U,V)!=0) return;
    if (ECP_BLS381_SVDP_DH(&U,W,&Z)!=0) return;

    OCT_copy(&VZ,V);
    OCT_joctet(&VZ,&Z);

    KDF2(sha,&VZ,P1,2*AESKEY_BLS381,&K);

    K1.len=K2.len=AESKEY_BLS381;
    for (i=0; i<AESKEY_BLS381; i++)
    {
        K1.val[i]=K.val[i];
        K2.val[i]=K.val[AESKEY_BLS381+i];
    }

    AES_CBC_IV0_ENCRYPT(&K1,M,C);

    OCT_jint(&L2,P2->len,8);

    len=C->len;
    OCT_joctet(C,P2);
    OCT_joctet(C,&L2);
    HMAC(sha,C,&K2,tlen,T);
    C->len=len;
}

/* IEEE1363 ECIES decryption. Decryption of ciphertext V,C,T using private key U outputs plaintext M */
int ECP_BLS381_ECIES_DECRYPT(int sha,octet *P1,octet *P2,octet *V,octet *C,octet *T,octet *U,octet *M)
{

    int i,len;
    char z[EFS_BLS381],vz[3*EFS_BLS381+1],k[2*AESKEY_BLS381],k1[AESKEY_BLS381],k2[AESKEY_BLS381],l2[8],tag[32];
    octet Z= {0,sizeof(z),z};
    octet VZ= {0,sizeof(vz),vz};
    octet K= {0,sizeof(k),k};
    octet K1= {0,sizeof(k1),k1};
    octet K2= {0,sizeof(k2),k2};
    octet L2= {0,sizeof(l2),l2};
    octet TAG= {0,sizeof(tag),tag};

    if (ECP_BLS381_SVDP_DH(U,V,&Z)!=0) return 0;

    OCT_copy(&VZ,V);
    OCT_joctet(&VZ,&Z);

    KDF2(sha,&VZ,P1,2*AESKEY_BLS381,&K);

    K1.len=K2.len=AESKEY_BLS381;
    for (i=0; i<AESKEY_BLS381; i++)
    {
        K1.val[i]=K.val[i];
        K2.val[i]=K.val[AESKEY_BLS381+i];
    }

    if (!AES_CBC_IV0_DECRYPT(&K1,C,M)) return 0;

    OCT_jint(&L2,P2->len,8);

    len=C->len;
    OCT_joctet(C,P2);
    OCT_joctet(C,&L2);
    HMAC(sha,C,&K2,T->len,&TAG);
    C->len=len;

    if (!OCT_comp(T,&TAG)) return 0;

    return 1;

}

#endif
