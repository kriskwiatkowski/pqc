#include <stddef.h>
#include <stdint.h>
#include "sha2.h"
#include "common/utils.h"

// Choose y or z depending on x.
#define Ch(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
// Majority returns 1 if at least 2 values are 1, otherwise 0.
#define Maj(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

// Definition of sigmas for SHA2 with 32-bit words (see FIPS PUB 180-4, 4.1.x)
#define Sigma0_32(x) (ROTR32(x, 2) ^ ROTR32(x,13) ^ ROTR32(x,22))
#define Sigma1_32(x) (ROTR32(x, 6) ^ ROTR32(x,11) ^ ROTR32(x,25))
#define sigma0_32(x) (ROTR32(x, 7) ^ ROTR32(x,18) ^ (x>>3))
#define sigma1_32(x) (ROTR32(x,17) ^ ROTR32(x,19) ^ (x>>10))


#define SHFT(T,SCHEDULE,a,b,c,d,e,f,g,h,K)                \
do {                                                      \
    SCHEDULE(schedule, T);                                \
    T1 = (h) + Sigma1_32(e) + Ch(e,f,g) + (K) + schedule; \
    T3 = T1 +  Sigma0_32(a) + Maj(a,b,c);                 \
    d += T1;                                              \
    h  = T3;                                              \
} while(0)
// Copy message schedule 't' to 'res'. Used when no more updates needed.
#define Wt(res,t) res = w[t]
// Copy message schedule to 'res' and prepare 'w[t]' to be used after next 16 rounds.
#define W(res, t)                                               \
do {                                                            \
    Wt(res,t);                                                  \
    w[t] += sigma1_32(w[(t+14)%16]) + w[(t+9)%16] + sigma0_32(w[(t+1)%16]); \
} while(0)

// SHA256 compression function.
static void compress(struct H_t *h0, const uint8_t *in) {
    // Working variables
    uint32_t a,b,c,d,e,f,g,h;
    // Temporary round variables T1,T2
    uint32_t T1,T3;
    // Temporary round variable used to store current W_t
    uint32_t schedule;
    // Message schedule
    uint32_t w[16];
    size_t j;

    for(j = 0; j<16; j++) {
        w[j] = LOAD32B(in + (j*4));
    }

    a = h0->h.h32[0];
    b = h0->h.h32[1];
    c = h0->h.h32[2];
    d = h0->h.h32[3];
    e = h0->h.h32[4];
    f = h0->h.h32[5];
    g = h0->h.h32[6];
    h = h0->h.h32[7];

    SHFT( 0,  W, a, b, c, d, e, f, g, h, 0x428A2F98);   /* t = 0 */
    SHFT( 1,  W, h, a, b, c, d, e, f, g, 0x71374491);
    SHFT( 2,  W, g, h, a, b, c, d, e, f, 0xB5C0FBCF);
    SHFT( 3,  W, f, g, h, a, b, c, d, e, 0xE9B5DBA5);
    SHFT( 4,  W, e, f, g, h, a, b, c, d, 0x3956C25B);
    SHFT( 5,  W, d, e, f, g, h, a, b, c, 0x59F111F1);
    SHFT( 6,  W, c, d, e, f, g, h, a, b, 0x923F82A4);
    SHFT( 7,  W, b, c, d, e, f, g, h, a, 0xAB1C5ED5);
    SHFT( 8,  W, a, b, c, d, e, f, g, h, 0xD807AA98);
    SHFT( 9,  W, h, a, b, c, d, e, f, g, 0x12835B01);
    SHFT(10,  W, g, h, a, b, c, d, e, f, 0x243185BE);   /* t = 10 */
    SHFT(11,  W, f, g, h, a, b, c, d, e, 0x550C7DC3);
    SHFT(12,  W, e, f, g, h, a, b, c, d, 0x72BE5D74);
    SHFT(13,  W, d, e, f, g, h, a, b, c, 0x80DEB1FE);
    SHFT(14,  W, c, d, e, f, g, h, a, b, 0x9BDC06A7);
    SHFT(15,  W, b, c, d, e, f, g, h, a, 0xC19BF174);

    SHFT( 0,  W, a, b, c, d, e, f, g, h, 0xE49B69C1);
    SHFT( 1,  W, h, a, b, c, d, e, f, g, 0xEFBE4786);
    SHFT( 2,  W, g, h, a, b, c, d, e, f, 0x0FC19DC6);
    SHFT( 3,  W, f, g, h, a, b, c, d, e, 0x240CA1CC);
    SHFT( 4,  W, e, f, g, h, a, b, c, d, 0x2DE92C6F);   /* t = 20 */
    SHFT( 5,  W, d, e, f, g, h, a, b, c, 0x4A7484AA);
    SHFT( 6,  W, c, d, e, f, g, h, a, b, 0x5CB0A9DC);
    SHFT( 7,  W, b, c, d, e, f, g, h, a, 0x76F988DA);
    SHFT( 8,  W, a, b, c, d, e, f, g, h, 0x983E5152);
    SHFT( 9,  W, h, a, b, c, d, e, f, g, 0xA831C66D);
    SHFT(10,  W, g, h, a, b, c, d, e, f, 0xB00327C8);
    SHFT(11,  W, f, g, h, a, b, c, d, e, 0xBF597FC7);
    SHFT(12,  W, e, f, g, h, a, b, c, d, 0xC6E00BF3);
    SHFT(13,  W, d, e, f, g, h, a, b, c, 0xD5A79147);
    SHFT(14,  W, c, d, e, f, g, h, a, b, 0x06CA6351);   /* t = 30 */
    SHFT(15,  W, b, c, d, e, f, g, h, a, 0x14292967);

    SHFT( 0,  W, a, b, c, d, e, f, g, h, 0x27B70A85);
    SHFT( 1,  W, h, a, b, c, d, e, f, g, 0x2E1B2138);
    SHFT( 2,  W, g, h, a, b, c, d, e, f, 0x4D2C6DFC);
    SHFT( 3,  W, f, g, h, a, b, c, d, e, 0x53380D13);
    SHFT( 4,  W, e, f, g, h, a, b, c, d, 0x650A7354);
    SHFT( 5,  W, d, e, f, g, h, a, b, c, 0x766A0ABB);
    SHFT( 6,  W, c, d, e, f, g, h, a, b, 0x81C2C92E);
    SHFT( 7,  W, b, c, d, e, f, g, h, a, 0x92722C85);
    SHFT( 8,  W, a, b, c, d, e, f, g, h, 0xA2BFE8A1);   /* t = 40 */
    SHFT( 9,  W, h, a, b, c, d, e, f, g, 0xA81A664B);
    SHFT(10,  W, g, h, a, b, c, d, e, f, 0xC24B8B70);
    SHFT(11,  W, f, g, h, a, b, c, d, e, 0xC76C51A3);
    SHFT(12,  W, e, f, g, h, a, b, c, d, 0xD192E819);
    SHFT(13,  W, d, e, f, g, h, a, b, c, 0xD6990624);
    SHFT(14,  W, c, d, e, f, g, h, a, b, 0xF40E3585);
    SHFT(15,  W, b, c, d, e, f, g, h, a, 0x106AA070);

    SHFT( 0, Wt, a, b, c, d, e, f, g, h, 0x19A4C116);
    SHFT( 1, Wt, h, a, b, c, d, e, f, g, 0x1E376C08);
    SHFT( 2, Wt, g, h, a, b, c, d, e, f, 0x2748774C);   /* t = 50 */
    SHFT( 3, Wt, f, g, h, a, b, c, d, e, 0x34B0BCB5);
    SHFT( 4, Wt, e, f, g, h, a, b, c, d, 0x391C0CB3);
    SHFT( 5, Wt, d, e, f, g, h, a, b, c, 0x4ED8AA4A);
    SHFT( 6, Wt, c, d, e, f, g, h, a, b, 0x5B9CCA4F);
    SHFT( 7, Wt, b, c, d, e, f, g, h, a, 0x682E6FF3);
    SHFT( 8, Wt, a, b, c, d, e, f, g, h, 0x748F82EE);
    SHFT( 9, Wt, h, a, b, c, d, e, f, g, 0x78A5636F);
    SHFT(10, Wt, g, h, a, b, c, d, e, f, 0x84C87814);
    SHFT(11, Wt, f, g, h, a, b, c, d, e, 0x8CC70208);
    SHFT(12, Wt, e, f, g, h, a, b, c, d, 0x90BEFFFA);   /* t = 60 */
    SHFT(13, Wt, d, e, f, g, h, a, b, c, 0xA4506CEB);
    SHFT(14, Wt, c, d, e, f, g, h, a, b, 0xBEF9A3F7);
    SHFT(15, Wt, b, c, d, e, f, g, h, a, 0xC67178F2);

    // Compute intermediate state and store in the context
    h0->h.h32[0] += a;
    h0->h.h32[1] += b;
    h0->h.h32[2] += c;
    h0->h.h32[3] += d;
    h0->h.h32[4] += e;
    h0->h.h32[5] += f;
    h0->h.h32[6] += g;
    h0->h.h32[7] += h;
}

void pqc_sha2_init_w32(struct pqc_sha2_t* ctx, bool is_224) {
    if (is_224) {
        ctx->h0.h.h32[0] = 0xc1059ed8;
        ctx->h0.h.h32[1] = 0x367CD507;
        ctx->h0.h.h32[2] = 0x3070DD17;
        ctx->h0.h.h32[3] = 0xF70E5939;
        ctx->h0.h.h32[4] = 0xFFC00B31;
        ctx->h0.h.h32[5] = 0x68581511;
        ctx->h0.h.h32[6] = 0x64F98FA7;
        ctx->h0.h.h32[7] = 0xBEFA4FA4;
        ctx->digest_sz = 28;
    } else {
        ctx->h0.h.h32[0] = 0x6A09E667;
        ctx->h0.h.h32[1] = 0xBB67AE85;
        ctx->h0.h.h32[2] = 0x3C6EF372;
        ctx->h0.h.h32[3] = 0xA54FF53A;
        ctx->h0.h.h32[4] = 0x510E527F;
        ctx->h0.h.h32[5] = 0x9B05688C;
        ctx->h0.h.h32[6] = 0x1F83D9AB;
        ctx->h0.h.h32[7] = 0x5BE0CD19;
        ctx->digest_sz = 32;
    }
    // ctx->op = sha2_compress_W32;
}
