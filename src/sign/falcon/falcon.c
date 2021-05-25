 /*
 * Copyright (c) 2017-2019  Falcon Project
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <randombytes.h>
#include <common/fips202.h>
#include "inner.h"

// log_2(MAX_N)
#define MAX_LOGN 10
// Ring degree for Falcon 1024
#define MAX_N 1U<<MAX_LOGN
// Maximal size of the ciphertext supported
#define MAX_CRYPTO_BYTES 1330
// Size of the seed
#define NONCELEN 40

int Zf(keypair)(uint8_t *pk, size_t pk_sz, uint8_t *sk, size_t sk_sz, size_t logn) {

    int8_t f[MAX_N], g[MAX_N], F[MAX_N];
    uint16_t h[MAX_N];
    uint8_t seed[48];
    shake256incctx ctx;
    unsigned savcw;
    size_t u, v;
    union {
        uint8_t b[FALCON_KEYGEN_TEMP_10];
        uint64_t dummy_u64;
        fpr dummy_fpr;
    } tmp;

    savcw = set_fpu_cw(2);

    // Generate key pair.
    randombytes(seed, ARRAY_LEN(seed));
    shake256_inc_init(&ctx);
    shake256_inc_absorb(&ctx,  seed, ARRAY_LEN(seed));
    shake256_inc_finalize(&ctx);
    Zf(keygen)(&ctx, f, g, F, NULL, h, logn, tmp.b);
    shake256_inc_ctx_release(&ctx);
    set_fpu_cw(savcw);

    // TODO: it seems those returns from trim_i8_encode and
    //       modq_encode  make no sense in this implementation.
    //       We support only logn=9 and 10.

    // Encode private key.
    sk[0] = 0x50 + logn;
    u = 1;
    v = Zf(trim_i8_encode)(sk + u, sk_sz - u,
        f, logn, Zf(max_fg_bits)[logn]);
    if (!v) return -1;

    u += v;
    v = Zf(trim_i8_encode)(sk + u, sk_sz - u,
        g, logn, Zf(max_fg_bits)[logn]);
    if (!v) return -1;

    u += v;
    v = Zf(trim_i8_encode)(sk + u, sk_sz - u,
        F, logn, Zf(max_FG_bits)[logn]);
    if (!v) return -1;

    // Encode public key.
    pk[0] = 0x00 + logn;
    v = Zf(modq_encode)(pk + 1, pk_sz - 1, h, logn);
    if (v != pk_sz - 1) return -1;

    return 0;
}

int Zf(sign)(
    uint8_t *sm, size_t *smsz,
    const uint8_t *m, size_t msz,
    const uint8_t *sk, size_t sk_sz, size_t logn) {
    union {
        uint8_t b[72 * MAX_N];
        uint64_t dummy_u64;
        fpr dummy_fpr;
    } tmp;
    int8_t f[MAX_N], g[MAX_N], F[MAX_N], G[MAX_N];
    union {
        int16_t sig[MAX_N];
        uint16_t hm[MAX_N];
    } r;
    uint8_t seed[48], nonce[NONCELEN];
    uint8_t esig[MAX_CRYPTO_BYTES - 2 - NONCELEN] = {0};
    size_t u, v, sigsz;
    unsigned savcw;
    shake256incctx ctx;

    // Decode the private key.
    if (sk[0] != 0x50 + logn) return -1;

    u = 1;
    v = Zf(trim_i8_decode)(f, logn, Zf(max_fg_bits)[logn],
        sk + u, sk_sz - u);
    if (!v) return -1;

    u += v;
    v = Zf(trim_i8_decode)(g, logn, Zf(max_fg_bits)[logn],
        sk + u, sk_sz - u);
    if (!v) return -1;

    u += v;
    v = Zf(trim_i8_decode)(F, logn, Zf(max_FG_bits)[logn],
        sk + u, sk_sz - u);
    if (!v) return -1;

    u += v;
    if (u != sk_sz) return -1;

    if (!Zf(complete_private)(G, f, g, F, logn, tmp.b)) {
        return -1;
    }

    randombytes(nonce, NONCELEN);

    // hash into vector
    shake256_inc_init(&ctx);
    shake256_inc_absorb(&ctx, nonce, NONCELEN);
    shake256_inc_absorb(&ctx, m, msz);
    shake256_inc_finalize(&ctx);
    Zf(hash_to_point_vartime)(&ctx, r.hm, logn);

    // initialize RNG
    randombytes(seed, sizeof seed);
    shake256_inc_reset(&ctx);
    shake256_inc_absorb(&ctx, seed, ARRAY_LEN(seed));
    shake256_inc_finalize(&ctx);
    savcw = set_fpu_cw(2);

    // compute signature
    Zf(sign_dyn)(r.sig, &ctx, f, g, F, G, r.hm, logn, tmp.b);
    shake256_inc_ctx_release(&ctx);
    set_fpu_cw(savcw);

    // Encode signature
    // 0x20: implementation supports compression algorithm (see 3.11.2)
    esig[0] = 0x20 + logn;
    sigsz = 1 + Zf(comp_encode)(esig + 1, ARRAY_LEN(esig) - 1, r.sig, logn);
    if (sigsz==1) return -1;

    // 2 bytes - signature length
    STORE16B(&sm[0], sigsz); u = 2;
    // 40 bytes: r (nonce)
    memcpy(&sm[u], nonce, NONCELEN); u+= NONCELEN;
    // rest: s (actuall signature)
    memcpy(&sm[u], esig, sigsz); u+= sigsz;

    *smsz = u;
    return 0;
}

int Zf(verify)(
    const uint8_t *m, size_t msz,
    const uint8_t *sm, size_t smsz,
    const uint8_t *pk, size_t pk_sz,
    size_t logn, size_t sig_sz) {

    union {
        uint8_t b[2 * MAX_N];
        uint64_t dummy_u64;
        fpr dummy_fpr;
    } tmp;
    const unsigned char *esig;
    uint16_t h[MAX_N], hm[MAX_N];
    int16_t sig[MAX_N];
    size_t local_sig_len;
    shake256incctx ctx;

    // Decode public key.
    if (pk[0] != 0x00 + logn) return -1;
    if (Zf(modq_decode)(h, logn, pk + 1, pk_sz - 1) != pk_sz - 1) {
        return -1;
    }
    Zf(to_ntt_monty)(h, logn);

    // Find nonce, signature, message length.
    if (smsz < 2 + NONCELEN) {
        return -1;
    }

    local_sig_len = LOAD16B(sm);
    if ((local_sig_len > sig_sz) ||
        (local_sig_len > (smsz - 2 - NONCELEN))) {
        return -1;
    }

    esig = &sm[2 + NONCELEN];
    // Currently this implementation supports only the compressed mode
    if (esig[0] != (0x20 + logn)) {
        return -1;
    }

    if (Zf(comp_decode)(sig, logn,
        esig + 1, local_sig_len - 1) != local_sig_len - 1) {
        return -1;
    }
    // hash nonce and a message into a vector
    shake256_inc_init(&ctx);
    shake256_inc_absorb(&ctx,  &sm[2], NONCELEN);
    shake256_inc_absorb(&ctx,  m, msz);
    shake256_inc_finalize(&ctx);
    Zf(hash_to_point_vartime)(&ctx, hm, logn);
    shake256_inc_ctx_release(&ctx);

    // Verify r
    if (!Zf(verify_raw)(hm, sig, h, logn, tmp.b)) {
        return -1;
    }

    return 0;
}
