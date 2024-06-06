#ifndef __BLST_SHA256_H__
#define __BLST_SHA256_H__

typedef struct {
    unsigned int h[8];
    unsigned long long N;
    unsigned char buf[64];
    size_t off;
} BLST_SHA256_CTX;

#endif
