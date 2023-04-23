#include "sha2.h"
#include "internal.h"

bool pqc_sha2_init(struct pqc_sha2_t *ctx, pqc_sha2_algs_t alg) {

    ccore_memset(ctx, 0, sizeof(*ctx));
    ctx->w32 = (alg < PQC_SHA2_W64);

    if(ctx->w32) {
        pqc_sha2_init_w32(ctx, alg == PQC_SHA2_224);
    }
    ctx->done = false;
    return true;
}

bool pqc_sha2_update(struct pqc_sha2_t *ctx, const uint8_t *msg, size_t len) {

}

bool pqc_sha2_sum(struct pqc_sha2_t *ctx, const uint8_t *msg, size_t len) {

}
