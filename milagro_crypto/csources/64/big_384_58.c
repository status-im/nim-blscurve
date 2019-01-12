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

/* AMCL basic functions for BIG type */
/* SU=m, SU is Stack Usage */

#include "big_384_58.h"

/* test a=0? */
int BIG_384_58_iszilch(BIG_384_58 a)
{
    int i;
    for (i=0; i<NLEN_384_58; i++)
        if (a[i]!=0) return 0;
    return 1;
}

/* test a=1? */
int BIG_384_58_isunity(BIG_384_58 a)
{
    int i;
    for(i=1; i<NLEN_384_58; i++)
        if (a[i]!=0) return 0;
    if (a[0]!=1) return 0;
    return 1;
}

/* test a=0? */
int BIG_384_58_diszilch(DBIG_384_58 a)
{
    int i;
    for (i=0; i<DNLEN_384_58; i++)
        if (a[i]!=0) return 0;
    return 1;
}

/* SU= 56 */
/* output a */
void BIG_384_58_output(BIG_384_58 a)
{
    BIG_384_58 b;
    int i,len;
    len=BIG_384_58_nbits(a);
    if (len%4==0) len/=4;
    else
    {
        len/=4;
        len++;
    }
    if (len<MODBYTES_384_58*2) len=MODBYTES_384_58*2;

    for (i=len-1; i>=0; i--)
    {
        BIG_384_58_copy(b,a);
        BIG_384_58_shr(b,i*4);
        printf("%01x",(unsigned int) b[0]&15);
    }
}

/* SU= 16 */
void BIG_384_58_rawoutput(BIG_384_58 a)
{
    int i;
    printf("(");
    for (i=0; i<NLEN_384_58-1; i++)
#if CHUNK==64
        printf("%"PRIxMAX",",(uintmax_t) a[i]);
    printf("%"PRIxMAX")",(uintmax_t) a[NLEN_384_58-1]);
#else
        printf("%x,",(unsigned int) a[i]);
    printf("%x)",(unsigned int) a[NLEN_384_58-1]);
#endif
}

/* Swap a and b if d=1 */
void BIG_384_58_cswap(BIG_384_58 a,BIG_384_58 b,int d)
{
    int i;
    chunk t,c=d;
    c=~(c-1);
#ifdef DEBUG_NORM
    for (i=0; i<NLEN_384_58+2; i++)
#else
    for (i=0; i<NLEN_384_58; i++)
#endif
    {
        t=c&(a[i]^b[i]);
        a[i]^=t;
        b[i]^=t;
    }
}

/* Move b to a if d=1 */
void BIG_384_58_cmove(BIG_384_58 f,BIG_384_58 g,int d)
{
    int i;
    chunk b=(chunk)-d;
#ifdef DEBUG_NORM
    for (i=0; i<NLEN_384_58+2; i++)
#else
    for (i=0; i<NLEN_384_58; i++)
#endif
    {
        f[i]^=(f[i]^g[i])&b;
    }
}

/* Move g to f if d=1 */
void BIG_384_58_dcmove(DBIG_384_58 f,DBIG_384_58 g,int d)
{
    int i;
    chunk b=(chunk)-d;
#ifdef DEBUG_NORM
    for (i=0; i<DNLEN_384_58+2; i++)
#else
    for (i=0; i<DNLEN_384_58; i++)
#endif
    {
        f[i]^=(f[i]^g[i])&b;
    }
}

/* convert BIG to/from bytes */
/* SU= 64 */
void BIG_384_58_toBytes(char *b,BIG_384_58 a)
{
    int i;
    BIG_384_58 c;
    BIG_384_58_copy(c,a);
	BIG_384_58_norm(c);
    for (i=MODBYTES_384_58-1; i>=0; i--)
    {
        b[i]=c[0]&0xff;
        BIG_384_58_fshr(c,8);
    }
}

/* SU= 16 */
void BIG_384_58_fromBytes(BIG_384_58 a,char *b)
{
    int i;
    BIG_384_58_zero(a);
    for (i=0; i<MODBYTES_384_58; i++)
    {
        BIG_384_58_fshl(a,8);
        a[0]+=(int)(unsigned char)b[i];
    }
#ifdef DEBUG_NORM
    a[MPV_384_58]=1;
    a[MNV_384_58]=0;
#endif
}

void BIG_384_58_fromBytesLen(BIG_384_58 a,char *b,int s)
{
    int i,len=s;
    BIG_384_58_zero(a);

    if (len>MODBYTES_384_58) len=MODBYTES_384_58;
    for (i=0; i<len; i++)
    {
        BIG_384_58_fshl(a,8);
        a[0]+=(int)(unsigned char)b[i];
    }
#ifdef DEBUG_NORM
    a[MPV_384_58]=1;
    a[MNV_384_58]=0;
#endif
}



/* SU= 88 */
void BIG_384_58_doutput(DBIG_384_58 a)
{
    DBIG_384_58 b;
    int i,len;
    BIG_384_58_dnorm(a);
    len=BIG_384_58_dnbits(a);
    if (len%4==0) len/=4;
    else
    {
        len/=4;
        len++;
    }

    for (i=len-1; i>=0; i--)
    {
        BIG_384_58_dcopy(b,a);
        BIG_384_58_dshr(b,i*4);
        printf("%01x",(unsigned int) b[0]&15);
    }
}


void BIG_384_58_drawoutput(DBIG_384_58 a)
{
    int i;
    printf("(");
    for (i=0; i<DNLEN_384_58-1; i++)
#if CHUNK==64
        printf("%"PRIxMAX",",(uintmax_t) a[i]);
    printf("%"PRIxMAX")",(uintmax_t) a[DNLEN_384_58-1]);
#else
        printf("%x,",(unsigned int) a[i]);
    printf("%x)",(unsigned int) a[DNLEN_384_58-1]);
#endif
}

/* Copy b=a */
void BIG_384_58_copy(BIG_384_58 b,BIG_384_58 a)
{
    int i;
    for (i=0; i<NLEN_384_58; i++)
        b[i]=a[i];
#ifdef DEBUG_NORM
    b[MPV_384_58]=a[MPV_384_58];
    b[MNV_384_58]=a[MNV_384_58];
#endif
}

/* Copy from ROM b=a */
void BIG_384_58_rcopy(BIG_384_58 b,const BIG_384_58 a)
{
    int i;
    for (i=0; i<NLEN_384_58; i++)
        b[i]=a[i];
#ifdef DEBUG_NORM
    b[MPV_384_58]=1;
    b[MNV_384_58]=0;
#endif
}

/* double length DBIG copy b=a */
void BIG_384_58_dcopy(DBIG_384_58 b,DBIG_384_58 a)
{
    int i;
    for (i=0; i<DNLEN_384_58; i++)
        b[i]=a[i];
#ifdef DEBUG_NORM
    b[DMPV_384_58]=a[DMPV_384_58];
    b[DMNV_384_58]=a[DMNV_384_58];
#endif
}

/* Copy BIG to bottom half of DBIG */
void BIG_384_58_dscopy(DBIG_384_58 b,BIG_384_58 a)
{
    int i;
    for (i=0; i<NLEN_384_58-1; i++)
        b[i]=a[i];

    b[NLEN_384_58-1]=a[NLEN_384_58-1]&BMASK_384_58; /* top word normalized */
    b[NLEN_384_58]=a[NLEN_384_58-1]>>BASEBITS_384_58;

    for (i=NLEN_384_58+1; i<DNLEN_384_58; i++) b[i]=0;
#ifdef DEBUG_NORM
    b[DMPV_384_58]=a[MPV_384_58];
    b[DMNV_384_58]=a[MNV_384_58];
#endif
}

/* Copy BIG to top half of DBIG */
void BIG_384_58_dsucopy(DBIG_384_58 b,BIG_384_58 a)
{
    int i;
    for (i=0; i<NLEN_384_58; i++)
        b[i]=0;
    for (i=NLEN_384_58; i<DNLEN_384_58; i++)
        b[i]=a[i-NLEN_384_58];
#ifdef DEBUG_NORM
    b[DMPV_384_58]=a[MPV_384_58];
    b[DMNV_384_58]=a[MNV_384_58];
#endif
}

/* Copy bottom half of DBIG to BIG */
void BIG_384_58_sdcopy(BIG_384_58 b,DBIG_384_58 a)
{
    int i;
    for (i=0; i<NLEN_384_58; i++)
        b[i]=a[i];
#ifdef DEBUG_NORM
    b[MPV_384_58]=a[DMPV_384_58];
    b[MNV_384_58]=a[DMNV_384_58];
#endif
}

/* Copy top half of DBIG to BIG */
void BIG_384_58_sducopy(BIG_384_58 b,DBIG_384_58 a)
{
    int i;
    for (i=0; i<NLEN_384_58; i++)
        b[i]=a[i+NLEN_384_58];
#ifdef DEBUG_NORM
    b[MPV_384_58]=a[DMPV_384_58];
    b[MNV_384_58]=a[DMNV_384_58];

#endif
}

/* Set a=0 */
void BIG_384_58_zero(BIG_384_58 a)
{
    int i;
    for (i=0; i<NLEN_384_58; i++)
        a[i]=0;
#ifdef DEBUG_NORM
    a[MPV_384_58]=a[MNV_384_58]=0;
#endif
}

void BIG_384_58_dzero(DBIG_384_58 a)
{
    int i;
    for (i=0; i<DNLEN_384_58; i++)
        a[i]=0;
#ifdef DEBUG_NORM
    a[DMPV_384_58]=a[DMNV_384_58]=0;
#endif
}

/* set a=1 */
void BIG_384_58_one(BIG_384_58 a)
{
    int i;
    a[0]=1;
    for (i=1; i<NLEN_384_58; i++)
        a[i]=0;
#ifdef DEBUG_NORM
    a[MPV_384_58]=1;
    a[MNV_384_58]=0;
#endif
}



/* Set c=a+b */
/* SU= 8 */
void BIG_384_58_add(BIG_384_58 c,BIG_384_58 a,BIG_384_58 b)
{
    int i;
    for (i=0; i<NLEN_384_58; i++)
        c[i]=a[i]+b[i];
#ifdef DEBUG_NORM
    c[MPV_384_58]=a[MPV_384_58]+b[MPV_384_58];
    c[MNV_384_58]=a[MNV_384_58]+b[MNV_384_58];
    if (c[MPV_384_58]>NEXCESS_384_58)  printf("add problem - positive digit overflow %d\n",c[MPV_384_58]);
    if (c[MNV_384_58]>NEXCESS_384_58)  printf("add problem - negative digit overflow %d\n",c[MNV_384_58]);

#endif
}

/* Set c=a or b */
void BIG_384_58_or(BIG_384_58 c,BIG_384_58 a,BIG_384_58 b)
{
    int i;
	BIG_384_58_norm(a);
	BIG_384_58_norm(b);
    for (i=0; i<NLEN_384_58; i++)
        c[i]=a[i]|b[i];
#ifdef DEBUG_NORM
    c[MPV_384_58]=1;
    c[MNV_384_58]=0;
#endif
}


/* Set c=c+d */
void BIG_384_58_inc(BIG_384_58 c,int d)
{
    BIG_384_58_norm(c);
    c[0]+=(chunk)d;
#ifdef DEBUG_NORM
    c[MPV_384_58]+=1;
#endif
}

/* Set c=a-b */
/* SU= 8 */
void BIG_384_58_sub(BIG_384_58 c,BIG_384_58 a,BIG_384_58 b)
{
    int i;
    for (i=0; i<NLEN_384_58; i++)
        c[i]=a[i]-b[i];
#ifdef DEBUG_NORM
    c[MPV_384_58]=a[MPV_384_58]+b[MNV_384_58];
    c[MNV_384_58]=a[MNV_384_58]+b[MPV_384_58];
    if (c[MPV_384_58]>NEXCESS_384_58)  printf("sub problem - positive digit overflow %d\n",c[MPV_384_58]);
    if (c[MNV_384_58]>NEXCESS_384_58)  printf("sub problem - negative digit overflow %d\n",c[MNV_384_58]);

#endif
}

/* SU= 8 */

void BIG_384_58_dsub(DBIG_384_58 c,DBIG_384_58 a,DBIG_384_58 b)
{
    int i;
    for (i=0; i<DNLEN_384_58; i++)
        c[i]=a[i]-b[i];
#ifdef DEBUG_NORM
    c[DMPV_384_58]=a[DMPV_384_58]+b[DMNV_384_58];
    c[DMNV_384_58]=a[DMNV_384_58]+b[DMPV_384_58];
    if (c[DMPV_384_58]>NEXCESS_384_58)  printf("double sub problem - positive digit overflow %d\n",c[DMPV_384_58]);
    if (c[DMNV_384_58]>NEXCESS_384_58)  printf("double sub problem - negative digit overflow %d\n",c[DMNV_384_58]);
#endif
}

void BIG_384_58_dadd(DBIG_384_58 c,DBIG_384_58 a,DBIG_384_58 b)
{
    int i;
    for (i=0; i<DNLEN_384_58; i++)
        c[i]=a[i]+b[i];
#ifdef DEBUG_NORM
    c[DMPV_384_58]=a[DMPV_384_58]+b[DMNV_384_58];
    c[DMNV_384_58]=a[DMNV_384_58]+b[DMPV_384_58];
    if (c[DMPV_384_58]>NEXCESS_384_58)  printf("double add problem - positive digit overflow %d\n",c[DMPV_384_58]);
    if (c[DMNV_384_58]>NEXCESS_384_58)  printf("double add problem - negative digit overflow %d\n",c[DMNV_384_58]);
#endif
}

/* Set c=c-1 */
void BIG_384_58_dec(BIG_384_58 c,int d)
{
    BIG_384_58_norm(c);
    c[0]-=(chunk)d;
#ifdef DEBUG_NORM
    c[MNV_384_58]+=1;
#endif
}

/* multiplication r=a*c by c<=NEXCESS_384_58 */
void BIG_384_58_imul(BIG_384_58 r,BIG_384_58 a,int c)
{
    int i;
    for (i=0; i<NLEN_384_58; i++) r[i]=a[i]*c;
#ifdef DEBUG_NORM
    r[MPV_384_58]=a[MPV_384_58]*c;
    r[MNV_384_58]=a[MNV_384_58]*c;
    if (r[MPV_384_58]>NEXCESS_384_58)  printf("int mul problem - positive digit overflow %d\n",r[MPV_384_58]);
    if (r[MNV_384_58]>NEXCESS_384_58)  printf("int mul problem - negative digit overflow %d\n",r[MNV_384_58]);

#endif
}

/* multiplication r=a*c by larger integer - c<=FEXCESS */
/* SU= 24 */
chunk BIG_384_58_pmul(BIG_384_58 r,BIG_384_58 a,int c)
{
    int i;
    chunk ak,carry=0;
    for (i=0; i<NLEN_384_58; i++)
    {
        ak=a[i];
        r[i]=0;
        carry=muladd_384_58(ak,(chunk)c,carry,&r[i]);
    }
#ifdef DEBUG_NORM
    r[MPV_384_58]=1;
    r[MNV_384_58]=0;
#endif
    return carry;
}

/* r/=3 */
/* SU= 16 */
int BIG_384_58_div3(BIG_384_58 r)
{
    int i;
    chunk ak,base,carry=0;
    BIG_384_58_norm(r);
    base=((chunk)1<<BASEBITS_384_58);
    for (i=NLEN_384_58-1; i>=0; i--)
    {
        ak=(carry*base+r[i]);
        r[i]=ak/3;
        carry=ak%3;
    }
    return (int)carry;
}

/* multiplication c=a*b by even larger integer b>FEXCESS, resulting in DBIG */
/* SU= 24 */
void BIG_384_58_pxmul(DBIG_384_58 c,BIG_384_58 a,int b)
{
    int j;
    chunk carry;
    BIG_384_58_dzero(c);
    carry=0;
    for (j=0; j<NLEN_384_58; j++)
        carry=muladd_384_58(a[j],(chunk)b,carry,&c[j]);
    c[NLEN_384_58]=carry;
#ifdef DEBUG_NORM
    c[DMPV_384_58]=1;
    c[DMNV_384_58]=0;
#endif
}

/* .. if you know the result will fit in a BIG, c must be distinct from a and b */
/* SU= 40 */
void BIG_384_58_smul(BIG_384_58 c,BIG_384_58 a,BIG_384_58 b)
{
    int i,j;
    chunk carry;

    BIG_384_58_zero(c);
    for (i=0; i<NLEN_384_58; i++)
    {
        carry=0;
        for (j=0; j<NLEN_384_58; j++)
        {
            if (i+j<NLEN_384_58)
                carry=muladd_384_58(a[i],b[j],carry,&c[i+j]);
        }
    }
#ifdef DEBUG_NORM
    c[MPV_384_58]=1;
    c[MNV_384_58]=0;
#endif

}

/* Set c=a*b */
/* SU= 72 */
void BIG_384_58_mul(DBIG_384_58 c,BIG_384_58 a,BIG_384_58 b)
{
    int i;
#ifdef dchunk
    dchunk t,co;
    dchunk s;
    dchunk d[NLEN_384_58];
    int k;
#endif

#ifdef DEBUG_NORM
    if ((a[MPV_384_58]!=1 && a[MPV_384_58]!=0) || a[MNV_384_58]!=0) printf("First input to mul not normed\n");
    if ((b[MPV_384_58]!=1 && b[MPV_384_58]!=0) || b[MNV_384_58]!=0) printf("Second input to mul not normed\n");
#endif

    /* Faster to Combafy it.. Let the compiler unroll the loops! */

#ifdef COMBA

    /* faster psuedo-Karatsuba method */
#ifdef UNWOUND

    /* Insert output of faster.c here */

#else
    for (i=0; i<NLEN_384_58; i++)
        d[i]=(dchunk)a[i]*b[i];

    s=d[0];
    t=s;
    c[0]=(chunk)t&BMASK_384_58;
    co=t>>BASEBITS_384_58;

    for (k=1; k<NLEN_384_58; k++)
    {
        s+=d[k];
        t=co+s;
        for (i=k; i>=1+k/2; i--) t+=(dchunk)(a[i]-a[k-i])*(b[k-i]-b[i]);
        c[k]=(chunk)t&BMASK_384_58;
        co=t>>BASEBITS_384_58;
    }
    for (k=NLEN_384_58; k<2*NLEN_384_58-1; k++)
    {
        s-=d[k-NLEN_384_58];
        t=co+s;
        for (i=NLEN_384_58-1; i>=1+k/2; i--) t+=(dchunk)(a[i]-a[k-i])*(b[k-i]-b[i]);
        c[k]=(chunk)t&BMASK_384_58;
        co=t>>BASEBITS_384_58;
    }
    c[2*NLEN_384_58-1]=(chunk)co;

#endif

#else
    int j;
    chunk carry;
    BIG_384_58_dzero(c);
    for (i=0; i<NLEN_384_58; i++)
    {
        carry=0;
        for (j=0; j<NLEN_384_58; j++)
            carry=muladd_384_58(a[i],b[j],carry,&c[i+j]);

        c[NLEN_384_58+i]=carry;
    }

#endif

#ifdef DEBUG_NORM
    c[DMPV_384_58]=1;
    c[DMNV_384_58]=0;
#endif
}

/* Set c=a*a */
/* SU= 80 */
void BIG_384_58_sqr(DBIG_384_58 c,BIG_384_58 a)
{
    int i,j;
#ifdef dchunk
    dchunk t,co;
#endif

#ifdef DEBUG_NORM
    if ((a[MPV_384_58]!=1 && a[MPV_384_58]!=0) || a[MNV_384_58]!=0) printf("Input to sqr not normed\n");
#endif
    /* Note 2*a[i] in loop below and extra addition */

#ifdef COMBA

#ifdef UNWOUND

    /* Insert output of faster.c here */

#else


    t=(dchunk)a[0]*a[0];
    c[0]=(chunk)t&BMASK_384_58;
    co=t>>BASEBITS_384_58;

    for (j=1; j<NLEN_384_58-1; )
    {
        t=(dchunk)a[j]*a[0];
        for (i=1; i<(j+1)/2; i++)
        {
            t+=(dchunk)a[j-i]*a[i];
        }
        t+=t;
        t+=co;
        c[j]=(chunk)t&BMASK_384_58;
        co=t>>BASEBITS_384_58;
        j++;
        t=(dchunk)a[j]*a[0];
        for (i=1; i<(j+1)/2; i++)
        {
            t+=(dchunk)a[j-i]*a[i];
        }
        t+=t;
        t+=co;
        t+=(dchunk)a[j/2]*a[j/2];
        c[j]=(chunk)t&BMASK_384_58;
        co=t>>BASEBITS_384_58;
        j++;
    }

    for (j=NLEN_384_58-1+NLEN_384_58%2; j<DNLEN_384_58-3; )
    {
        t=(dchunk)a[NLEN_384_58-1]*a[j-NLEN_384_58+1];
        for (i=j-NLEN_384_58+2; i<(j+1)/2; i++)
        {
            t+=(dchunk)a[j-i]*a[i];
        }
        t+=t;
        t+=co;
        c[j]=(chunk)t&BMASK_384_58;
        co=t>>BASEBITS_384_58;
        j++;
        t=(dchunk)a[NLEN_384_58-1]*a[j-NLEN_384_58+1];
        for (i=j-NLEN_384_58+2; i<(j+1)/2; i++)
        {
            t+=(dchunk)a[j-i]*a[i];
        }
        t+=t;
        t+=co;
        t+=(dchunk)a[j/2]*a[j/2];
        c[j]=(chunk)t&BMASK_384_58;
        co=t>>BASEBITS_384_58;
        j++;
    }

    t=(dchunk)a[NLEN_384_58-2]*a[NLEN_384_58-1];
    t+=t;
    t+=co;
    c[DNLEN_384_58-3]=(chunk)t&BMASK_384_58;
    co=t>>BASEBITS_384_58;

    t=(dchunk)a[NLEN_384_58-1]*a[NLEN_384_58-1]+co;
    c[DNLEN_384_58-2]=(chunk)t&BMASK_384_58;
    co=t>>BASEBITS_384_58;
    c[DNLEN_384_58-1]=(chunk)co;


#endif

#else
    chunk carry;
    BIG_384_58_dzero(c);
    for (i=0; i<NLEN_384_58; i++)
    {
        carry=0;
        for (j=i+1; j<NLEN_384_58; j++)
            carry=muladd_384_58(a[i],a[j],carry,&c[i+j]);
        c[NLEN_384_58+i]=carry;
    }

    for (i=0; i<DNLEN_384_58; i++) c[i]*=2;

    for (i=0; i<NLEN_384_58; i++)
        c[2*i+1]+=muladd_384_58(a[i],a[i],0,&c[2*i]);

    BIG_384_58_dnorm(c);
#endif


#ifdef DEBUG_NORM
    c[DMPV_384_58]=1;
    c[DMNV_384_58]=0;
#endif

}

/* Montgomery reduction */
void BIG_384_58_monty(BIG_384_58 a,BIG_384_58 md,chunk MC,DBIG_384_58 d)
{
    int i,k;

#ifdef dchunk
    dchunk t,c,s;
    dchunk dd[NLEN_384_58];
    chunk v[NLEN_384_58];
#endif

#ifdef COMBA

#ifdef UNWOUND

    /* Insert output of faster.c here */

#else

    t=d[0];
    v[0]=((chunk)t*MC)&BMASK_384_58;
    t+=(dchunk)v[0]*md[0];
    c=(t>>BASEBITS_384_58)+d[1];
    s=0;

    for (k=1; k<NLEN_384_58; k++)
    {
        t=c+s+(dchunk)v[0]*md[k];
        for (i=k-1; i>k/2; i--) t+=(dchunk)(v[k-i]-v[i])*(md[i]-md[k-i]);
        v[k]=((chunk)t*MC)&BMASK_384_58;
        t+=(dchunk)v[k]*md[0];
        c=(t>>BASEBITS_384_58)+d[k+1];
        dd[k]=(dchunk)v[k]*md[k];
        s+=dd[k];
    }
    for (k=NLEN_384_58; k<2*NLEN_384_58-1; k++)
    {
        t=c+s;
        for (i=NLEN_384_58-1; i>=1+k/2; i--) t+=(dchunk)(v[k-i]-v[i])*(md[i]-md[k-i]);
        a[k-NLEN_384_58]=(chunk)t&BMASK_384_58;
        c=(t>>BASEBITS_384_58)+d[k+1];
        s-=dd[k-NLEN_384_58+1];
    }
    a[NLEN_384_58-1]=(chunk)c&BMASK_384_58;

#endif



#else
    int j;
    chunk m,carry;
    for (i=0; i<NLEN_384_58; i++)
    {
        if (MC==-1) m=(-d[i])&BMASK_384_58;
        else
        {
            if (MC==1) m=d[i];
            else m=(MC*d[i])&BMASK_384_58;
        }
        carry=0;
        for (j=0; j<NLEN_384_58; j++)
            carry=muladd_384_58(m,md[j],carry,&d[i+j]);
        d[NLEN_384_58+i]+=carry;
    }
    BIG_384_58_sducopy(a,d);
    BIG_384_58_norm(a);

#endif

#ifdef DEBUG_NORM
    a[MPV_384_58]=1;
    a[MNV_384_58]=0;
#endif
}

/* General shift left of a by n bits */
/* a MUST be normalised */
/* SU= 32 */
void BIG_384_58_shl(BIG_384_58 a,int k)
{
    int i;
    int n=k%BASEBITS_384_58;
    int m=k/BASEBITS_384_58;

    a[NLEN_384_58-1]=((a[NLEN_384_58-1-m]<<n));
    if (NLEN_384_58>=m+2) a[NLEN_384_58-1]|=(a[NLEN_384_58-m-2]>>(BASEBITS_384_58-n));

    for (i=NLEN_384_58-2; i>m; i--)
        a[i]=((a[i-m]<<n)&BMASK_384_58)|(a[i-m-1]>>(BASEBITS_384_58-n));
    a[m]=(a[0]<<n)&BMASK_384_58;
    for (i=0; i<m; i++) a[i]=0;

}

/* Fast shift left of a by n bits, where n less than a word, Return excess (but store it as well) */
/* a MUST be normalised */
/* SU= 16 */
int BIG_384_58_fshl(BIG_384_58 a,int n)
{
    int i;

    a[NLEN_384_58-1]=((a[NLEN_384_58-1]<<n))|(a[NLEN_384_58-2]>>(BASEBITS_384_58-n)); /* top word not masked */
    for (i=NLEN_384_58-2; i>0; i--)
        a[i]=((a[i]<<n)&BMASK_384_58)|(a[i-1]>>(BASEBITS_384_58-n));
    a[0]=(a[0]<<n)&BMASK_384_58;

    return (int)(a[NLEN_384_58-1]>>((8*MODBYTES_384_58)%BASEBITS_384_58)); /* return excess - only used in ff.c */
}

/* double length left shift of a by k bits - k can be > BASEBITS , a MUST be normalised */
/* SU= 32 */
void BIG_384_58_dshl(DBIG_384_58 a,int k)
{
    int i;
    int n=k%BASEBITS_384_58;
    int m=k/BASEBITS_384_58;

    a[DNLEN_384_58-1]=((a[DNLEN_384_58-1-m]<<n))|(a[DNLEN_384_58-m-2]>>(BASEBITS_384_58-n));

    for (i=DNLEN_384_58-2; i>m; i--)
        a[i]=((a[i-m]<<n)&BMASK_384_58)|(a[i-m-1]>>(BASEBITS_384_58-n));
    a[m]=(a[0]<<n)&BMASK_384_58;
    for (i=0; i<m; i++) a[i]=0;

}

/* General shift right of a by k bits */
/* a MUST be normalised */
/* SU= 32 */
void BIG_384_58_shr(BIG_384_58 a,int k)
{
    int i;
    int n=k%BASEBITS_384_58;
    int m=k/BASEBITS_384_58;
    for (i=0; i<NLEN_384_58-m-1; i++)
        a[i]=(a[m+i]>>n)|((a[m+i+1]<<(BASEBITS_384_58-n))&BMASK_384_58);
    if (NLEN_384_58>m)  a[NLEN_384_58-m-1]=a[NLEN_384_58-1]>>n;
    for (i=NLEN_384_58-m; i<NLEN_384_58; i++) a[i]=0;

}

/* Fast combined shift, subtract and norm. Return sign of result */
int BIG_384_58_ssn(BIG_384_58 r,BIG_384_58 a,BIG_384_58 m)
{
	int i,n=NLEN_384_58-1;
	chunk carry;
	m[0]=(m[0]>>1)|((m[1]<<(BASEBITS_384_58-1))&BMASK_384_58);
	r[0]=a[0]-m[0];
    carry=r[0]>>BASEBITS_384_58;
    r[0]&=BMASK_384_58;
    
	for (i=1;i<n;i++)
	{
		m[i]=(m[i]>>1)|((m[i+1]<<(BASEBITS_384_58-1))&BMASK_384_58);
		r[i]=a[i]-m[i]+carry;
		carry=r[i]>>BASEBITS_384_58;
		r[i]&=BMASK_384_58;
	}
	
	m[n]>>=1;
	r[n]=a[n]-m[n]+carry;
#ifdef DEBUG_NORM
    r[MPV_384_58]=1;
    r[MNV_384_58]=0;
#endif
	return ((r[n]>>(CHUNK-1))&1);
}

/* Faster shift right of a by k bits. Return shifted out part */
/* a MUST be normalised */
/* SU= 16 */
int BIG_384_58_fshr(BIG_384_58 a,int k)
{
    int i;
    chunk r=a[0]&(((chunk)1<<k)-1); /* shifted out part */
    for (i=0; i<NLEN_384_58-1; i++)
        a[i]=(a[i]>>k)|((a[i+1]<<(BASEBITS_384_58-k))&BMASK_384_58);
    a[NLEN_384_58-1]=a[NLEN_384_58-1]>>k;
    return (int)r;
}

/* double length right shift of a by k bits - can be > BASEBITS */
/* SU= 32 */
void BIG_384_58_dshr(DBIG_384_58 a,int k)
{
    int i;
    int n=k%BASEBITS_384_58;
    int m=k/BASEBITS_384_58;
    for (i=0; i<DNLEN_384_58-m-1; i++)
        a[i]=(a[m+i]>>n)|((a[m+i+1]<<(BASEBITS_384_58-n))&BMASK_384_58);
    a[DNLEN_384_58-m-1]=a[DNLEN_384_58-1]>>n;
    for (i=DNLEN_384_58-m; i<DNLEN_384_58; i++ ) a[i]=0;
}

/* Split DBIG d into two BIGs t|b. Split happens at n bits, where n falls into NLEN word */
/* d MUST be normalised */
/* SU= 24 */
chunk BIG_384_58_split(BIG_384_58 t,BIG_384_58 b,DBIG_384_58 d,int n)
{
    int i;
    chunk nw,carry=0;
    int m=n%BASEBITS_384_58;

    if (m==0)
    {
        for (i=0; i<NLEN_384_58; i++) b[i]=d[i];
        if (t!=b)
        {
            for (i=NLEN_384_58; i<2*NLEN_384_58; i++) t[i-NLEN_384_58]=d[i];
            carry=t[NLEN_384_58-1]>>BASEBITS_384_58;
            t[NLEN_384_58-1]=t[NLEN_384_58-1]&BMASK_384_58; /* top word normalized */
        }
        return carry;
    }

    for (i=0; i<NLEN_384_58-1; i++) b[i]=d[i];

    b[NLEN_384_58-1]=d[NLEN_384_58-1]&(((chunk)1<<m)-1);

    if (t!=b)
    {
        carry=(d[DNLEN_384_58-1]<<(BASEBITS_384_58-m));
        for (i=DNLEN_384_58-2; i>=NLEN_384_58-1; i--)
        {
            nw=(d[i]>>m)|carry;
            carry=(d[i]<<(BASEBITS_384_58-m))&BMASK_384_58;
            t[i-NLEN_384_58+1]=nw;
        }
    }
#ifdef DEBUG_NORM
    t[MPV_384_58]=1;
    t[MNV_384_58]=0;
    b[MPV_384_58]=1;
    b[MNV_384_58]=0;
#endif
    return carry;
}

/* you gotta keep the sign of carry! Look - no branching! */
/* Note that sign bit is needed to disambiguate between +ve and -ve values */
/* normalise BIG - force all digits < 2^BASEBITS */
chunk BIG_384_58_norm(BIG_384_58 a)
{
    int i;
    chunk d,carry=0;
    for (i=0; i<NLEN_384_58-1; i++)
    {
        d=a[i]+carry;
        a[i]=d&BMASK_384_58;
        carry=d>>BASEBITS_384_58;
    }
    a[NLEN_384_58-1]=(a[NLEN_384_58-1]+carry);

#ifdef DEBUG_NORM
    a[MPV_384_58]=1;
    a[MNV_384_58]=0;
#endif
    return (a[NLEN_384_58-1]>>((8*MODBYTES_384_58)%BASEBITS_384_58));  /* only used in ff.c */
}

void BIG_384_58_dnorm(DBIG_384_58 a)
{
    int i;
    chunk d,carry=0;
    for (i=0; i<DNLEN_384_58-1; i++)
    {
        d=a[i]+carry;
        a[i]=d&BMASK_384_58;
        carry=d>>BASEBITS_384_58;
    }
    a[DNLEN_384_58-1]=(a[DNLEN_384_58-1]+carry);
#ifdef DEBUG_NORM
    a[DMPV_384_58]=1;
    a[DMNV_384_58]=0;
#endif
}

/* Compare a and b. Return 1 for a>b, -1 for a<b, 0 for a==b */
/* a and b MUST be normalised before call */
int BIG_384_58_comp(BIG_384_58 a,BIG_384_58 b)
{
    int i;
    for (i=NLEN_384_58-1; i>=0; i--)
    {
        if (a[i]==b[i]) continue;
        if (a[i]>b[i]) return 1;
        else  return -1;
    }
    return 0;
}

int BIG_384_58_dcomp(DBIG_384_58 a,DBIG_384_58 b)
{
    int i;
    for (i=DNLEN_384_58-1; i>=0; i--)
    {
        if (a[i]==b[i]) continue;
        if (a[i]>b[i]) return 1;
        else  return -1;
    }
    return 0;
}

/* return number of bits in a */
/* SU= 8 */
int BIG_384_58_nbits(BIG_384_58 a)
{
    int bts,k=NLEN_384_58-1;
	BIG_384_58 t;
    chunk c;
	BIG_384_58_copy(t,a);
    BIG_384_58_norm(t);
    while (k>=0 && t[k]==0) k--;
    if (k<0) return 0;
    bts=BASEBITS_384_58*k;
    c=t[k];
    while (c!=0)
    {
        c/=2;
        bts++;
    }
    return bts;
}

/* SU= 8, Calculate number of bits in a DBIG - output normalised */
int BIG_384_58_dnbits(DBIG_384_58 a)
{
    int bts,k=DNLEN_384_58-1;
	DBIG_384_58 t;
    chunk c;
	BIG_384_58_dcopy(t,a);
    BIG_384_58_dnorm(t);
    while (k>=0 && t[k]==0) k--;
    if (k<0) return 0;
    bts=BASEBITS_384_58*k;
    c=t[k];
    while (c!=0)
    {
        c/=2;
        bts++;
    }
    return bts;
}


/* Set b=b mod c */
/* SU= 16 */
void BIG_384_58_mod(BIG_384_58 b,BIG_384_58 c1)
{
    int k=0;
    BIG_384_58 r; /**/
	BIG_384_58 c;
	BIG_384_58_copy(c,c1);

    BIG_384_58_norm(b);
    if (BIG_384_58_comp(b,c)<0)
        return;
    do
    {
        BIG_384_58_fshl(c,1);
        k++;
    }
    while (BIG_384_58_comp(b,c)>=0);

    while (k>0)
    {
        BIG_384_58_fshr(c,1);

// constant time...
        BIG_384_58_sub(r,b,c);
        BIG_384_58_norm(r);
        BIG_384_58_cmove(b,r,1-((r[NLEN_384_58-1]>>(CHUNK-1))&1));
        k--;
    }
}

/* Set a=b mod c, b is destroyed. Slow but rarely used. */
/* SU= 96 */
void BIG_384_58_dmod(BIG_384_58 a,DBIG_384_58 b,BIG_384_58 c)
{
    int k=0;
    DBIG_384_58 m,r;
    BIG_384_58_dnorm(b);
    BIG_384_58_dscopy(m,c);

    if (BIG_384_58_dcomp(b,m)<0)
    {
        BIG_384_58_sdcopy(a,b);
        return;
    }

    do
    {
        BIG_384_58_dshl(m,1);
        k++;
    }
    while (BIG_384_58_dcomp(b,m)>=0);

    while (k>0)
    {
        BIG_384_58_dshr(m,1);
// constant time...
        BIG_384_58_dsub(r,b,m);
        BIG_384_58_dnorm(r);
        BIG_384_58_dcmove(b,r,1-((r[DNLEN_384_58-1]>>(CHUNK-1))&1));

        k--;
    }
    BIG_384_58_sdcopy(a,b);
}

/* Set a=b/c,  b is destroyed. Slow but rarely used. */
/* SU= 136 */

void BIG_384_58_ddiv(BIG_384_58 a,DBIG_384_58 b,BIG_384_58 c)
{
    int d,k=0;
    DBIG_384_58 m,dr;
    BIG_384_58 e,r;
    BIG_384_58_dnorm(b);
    BIG_384_58_dscopy(m,c);

    BIG_384_58_zero(a);
    BIG_384_58_zero(e);
    BIG_384_58_inc(e,1);

    while (BIG_384_58_dcomp(b,m)>=0)
    {
        BIG_384_58_fshl(e,1);
        BIG_384_58_dshl(m,1);
        k++;
    }

    while (k>0)
    {
        BIG_384_58_dshr(m,1);
        BIG_384_58_fshr(e,1);

        BIG_384_58_dsub(dr,b,m);
        BIG_384_58_dnorm(dr);
        d=1-((dr[DNLEN_384_58-1]>>(CHUNK-1))&1);
        BIG_384_58_dcmove(b,dr,d);

        BIG_384_58_add(r,a,e);
        BIG_384_58_norm(r);
        BIG_384_58_cmove(a,r,d);

        k--;
    }
}

/* SU= 136 */

void BIG_384_58_sdiv(BIG_384_58 a,BIG_384_58 c)
{
    int d,k=0;
    BIG_384_58 m,e,b,r;
    BIG_384_58_norm(a);
    BIG_384_58_copy(b,a);
    BIG_384_58_copy(m,c);

    BIG_384_58_zero(a);
    BIG_384_58_zero(e);
    BIG_384_58_inc(e,1);

    while (BIG_384_58_comp(b,m)>=0)
    {
        BIG_384_58_fshl(e,1);
        BIG_384_58_fshl(m,1);
        k++;
    }

    while (k>0)
    {
        BIG_384_58_fshr(m,1);
        BIG_384_58_fshr(e,1);

        BIG_384_58_sub(r,b,m);
        BIG_384_58_norm(r);
        d=1-((r[NLEN_384_58-1]>>(CHUNK-1))&1);
        BIG_384_58_cmove(b,r,d);

        BIG_384_58_add(r,a,e);
        BIG_384_58_norm(r);
        BIG_384_58_cmove(a,r,d);
        k--;
    }
}

/* return LSB of a */
int BIG_384_58_parity(BIG_384_58 a)
{
    return a[0]%2;
}

/* return n-th bit of a */
/* SU= 16 */
int BIG_384_58_bit(BIG_384_58 a,int n)
{
    if (a[n/BASEBITS_384_58]&((chunk)1<<(n%BASEBITS_384_58))) return 1;
    else return 0;
}

/* return last n bits of a, where n is small < BASEBITS */
/* SU= 16 */
int BIG_384_58_lastbits(BIG_384_58 a,int n)
{
    int msk=(1<<n)-1;
    BIG_384_58_norm(a);
    return ((int)a[0])&msk;
}

/* get 8*MODBYTES size random number */
// void BIG_384_58_random(BIG_384_58 m,csprng *rng)
// {
//     int i,b,j=0,r=0;
//     int len=8*MODBYTES_384_58;
// 
//     BIG_384_58_zero(m);
//     /* generate random BIG */
//     for (i=0; i<len; i++)
//     {
//         if (j==0) r=RAND_byte(rng);
//         else r>>=1;
//         b=r&1;
//         BIG_384_58_shl(m,1);
//         m[0]+=b;
//         j++;
//         j&=7;
//     }
// 
// #ifdef DEBUG_NORM
//     m[MPV_384_58]=1;
//     m[MNV_384_58]=0;
// #endif
// }

/* get random BIG from rng, modulo q. Done one bit at a time, so its portable */

// void BIG_384_58_randomnum(BIG_384_58 m,BIG_384_58 q,csprng *rng)
// {
//     int i,b,j=0,r=0;
//     DBIG_384_58 d;
//     BIG_384_58_dzero(d);
//     /* generate random DBIG */
//     for (i=0; i<2*BIG_384_58_nbits(q); i++)
//     {
//         if (j==0) r=RAND_byte(rng);
//         else r>>=1;
//         b=r&1;
//         BIG_384_58_dshl(d,1);
//         d[0]+=b;
//         j++;
//         j&=7;
//     }
//     /* reduce modulo a BIG. Removes bias */
//     BIG_384_58_dmod(m,d,q);
// #ifdef DEBUG_NORM
//     m[MPV_384_58]=1;
//     m[MNV_384_58]=0;
// #endif
// }

/* Set r=a*b mod m */
/* SU= 96 */
void BIG_384_58_modmul(BIG_384_58 r,BIG_384_58 a1,BIG_384_58 b1,BIG_384_58 m)
{
    DBIG_384_58 d;
	BIG_384_58 a,b;
	BIG_384_58_copy(a,a1);
	BIG_384_58_copy(b,b1);
    BIG_384_58_mod(a,m);
    BIG_384_58_mod(b,m);

    BIG_384_58_mul(d,a,b);
    BIG_384_58_dmod(r,d,m);
}

/* Set a=a*a mod m */
/* SU= 88 */
void BIG_384_58_modsqr(BIG_384_58 r,BIG_384_58 a1,BIG_384_58 m)
{
    DBIG_384_58 d;
	BIG_384_58 a;
	BIG_384_58_copy(a,a1);
    BIG_384_58_mod(a,m);
    BIG_384_58_sqr(d,a);
    BIG_384_58_dmod(r,d,m);
}

/* Set r=-a mod m */
/* SU= 16 */
void BIG_384_58_modneg(BIG_384_58 r,BIG_384_58 a1,BIG_384_58 m)
{
	BIG_384_58 a;
	BIG_384_58_copy(a,a1);
    BIG_384_58_mod(a,m);
    BIG_384_58_sub(r,m,a);
}

/* Set a=a/b mod m */
/* SU= 136 */
void BIG_384_58_moddiv(BIG_384_58 r,BIG_384_58 a1,BIG_384_58 b1,BIG_384_58 m)
{
    DBIG_384_58 d;
    BIG_384_58 z;
	BIG_384_58 a,b;
	BIG_384_58_copy(a,a1);
	BIG_384_58_copy(b,b1);

    BIG_384_58_mod(a,m);
    BIG_384_58_invmodp(z,b,m);

    BIG_384_58_mul(d,a,z);
    BIG_384_58_dmod(r,d,m);
}

/* Get jacobi Symbol (a/p). Returns 0, 1 or -1 */
/* SU= 216 */
int BIG_384_58_jacobi(BIG_384_58 a,BIG_384_58 p)
{
    int n8,k,m=0;
    BIG_384_58 t,x,n,zilch,one;
    BIG_384_58_one(one);
    BIG_384_58_zero(zilch);
    if (BIG_384_58_parity(p)==0 || BIG_384_58_comp(a,zilch)==0 || BIG_384_58_comp(p,one)<=0) return 0;
    BIG_384_58_norm(a);
    BIG_384_58_copy(x,a);
    BIG_384_58_copy(n,p);
    BIG_384_58_mod(x,p);

    while (BIG_384_58_comp(n,one)>0)
    {
        if (BIG_384_58_comp(x,zilch)==0) return 0;
        n8=BIG_384_58_lastbits(n,3);
        k=0;
        while (BIG_384_58_parity(x)==0)
        {
            k++;
            BIG_384_58_shr(x,1);
        }
        if (k%2==1) m+=(n8*n8-1)/8;
        m+=(n8-1)*(BIG_384_58_lastbits(x,2)-1)/4;
        BIG_384_58_copy(t,n);

        BIG_384_58_mod(t,x);
        BIG_384_58_copy(n,x);
        BIG_384_58_copy(x,t);
        m%=2;

    }
    if (m==0) return 1;
    else return -1;
}

/* Set r=1/a mod p. Binary method */
/* SU= 240 */
void BIG_384_58_invmodp(BIG_384_58 r,BIG_384_58 a,BIG_384_58 p)
{
    BIG_384_58 u,v,x1,x2,t,one;
    BIG_384_58_mod(a,p);
    BIG_384_58_copy(u,a);
    BIG_384_58_copy(v,p);
    BIG_384_58_one(one);
    BIG_384_58_copy(x1,one);
    BIG_384_58_zero(x2);

    while (BIG_384_58_comp(u,one)!=0 && BIG_384_58_comp(v,one)!=0)
    {
        while (BIG_384_58_parity(u)==0)
        {
            BIG_384_58_fshr(u,1);
            if (BIG_384_58_parity(x1)!=0)
            {
                BIG_384_58_add(x1,p,x1);
                BIG_384_58_norm(x1);
            }
            BIG_384_58_fshr(x1,1);
        }
        while (BIG_384_58_parity(v)==0)
        {
            BIG_384_58_fshr(v,1);
            if (BIG_384_58_parity(x2)!=0)
            {
                BIG_384_58_add(x2,p,x2);
                BIG_384_58_norm(x2);
            }
            BIG_384_58_fshr(x2,1);
        }
        if (BIG_384_58_comp(u,v)>=0)
        {
            BIG_384_58_sub(u,u,v);
            BIG_384_58_norm(u);
            if (BIG_384_58_comp(x1,x2)>=0) BIG_384_58_sub(x1,x1,x2);
            else
            {
                BIG_384_58_sub(t,p,x2);
                BIG_384_58_add(x1,x1,t);
            }
            BIG_384_58_norm(x1);
        }
        else
        {
            BIG_384_58_sub(v,v,u);
            BIG_384_58_norm(v);
            if (BIG_384_58_comp(x2,x1)>=0) BIG_384_58_sub(x2,x2,x1);
            else
            {
                BIG_384_58_sub(t,p,x1);
                BIG_384_58_add(x2,x2,t);
            }
            BIG_384_58_norm(x2);
        }
    }
    if (BIG_384_58_comp(u,one)==0)
        BIG_384_58_copy(r,x1);
    else
        BIG_384_58_copy(r,x2);
}

/* set x = x mod 2^m */
void BIG_384_58_mod2m(BIG_384_58 x,int m)
{
    int i,wd,bt;
    chunk msk;
    BIG_384_58_norm(x);

    wd=m/BASEBITS_384_58;
    bt=m%BASEBITS_384_58;
    msk=((chunk)1<<bt)-1;
    x[wd]&=msk;
    for (i=wd+1; i<NLEN_384_58; i++) x[i]=0;
}

// new
/* Convert to DBIG number from byte array of given length */
void BIG_384_58_dfromBytesLen(DBIG_384_58 a,char *b,int s)
{
    int i,len=s;
    BIG_384_58_dzero(a);

    for (i=0; i<len; i++)
    {
        BIG_384_58_dshl(a,8);
        a[0]+=(int)(unsigned char)b[i];
    }
#ifdef DEBUG_NORM
    a[DMPV_384_58]=1;
    a[DMNV_384_58]=0;
#endif
}


