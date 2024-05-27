#include "../../vendor/blst/src/sha256.h"
#include "./blst_sha256.h"

/*Copied from nimbase.h*/
#if (defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L)
#define MY_STATIC_ASSERT(x, msg) _Static_assert((x), msg)
#elif defined(__cplusplus)
#define MY_STATIC_ASSERT(x, msg) static_assert((x), msg)
#else
#define MY_STATIC_ASSERT(x, msg) typedef int MY_STATIC_ASSERT_AUX[(x) ? 1 : -1];
#endif

MY_STATIC_ASSERT(sizeof(BLST_SHA256_CTX) == sizeof(SHA256_CTX),
  "The size of BLST_SHA256_CTX not equal to the size of SHA256_CTX");

void blst_sha256_init(BLST_SHA256_CTX *ctx) {
  sha256_init((SHA256_CTX*)ctx);
}

void blst_sha256_update(BLST_SHA256_CTX *ctx, const void *_inp, size_t len) {
  sha256_update((SHA256_CTX*)ctx, _inp, len);
}

void blst_sha256_final(unsigned char md[32], BLST_SHA256_CTX *ctx) {
  sha256_final(md, (SHA256_CTX*)ctx);
}
