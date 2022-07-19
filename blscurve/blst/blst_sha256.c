#include "../../vendor/blst/src/sha256.h"

void blst_sha256_init(SHA256_CTX *ctx) {
  sha256_init(ctx);
}

void blst_sha256_update(SHA256_CTX *ctx, const void *_inp, size_t len) {
  sha256_update(ctx, _inp, len);
}

void blst_sha256_final(unsigned char md[32], SHA256_CTX *ctx) {
  sha256_final(md, ctx);
}
