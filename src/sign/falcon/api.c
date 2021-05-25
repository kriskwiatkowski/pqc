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

#include <common/utils.h>
#include "inner.h"
#include "api.h"

// Forward declarations of signature API
int Zf(keypair)(uint8_t *pk, size_t pk_sz, uint8_t *sk, size_t sk_sz, size_t logn);
int Zf(sign)(uint8_t *sm, size_t *smsz, const uint8_t *m, size_t msz,
    const uint8_t *sk, size_t sk_sz, size_t logn);
int Zf(verify)(const uint8_t *m, size_t msz, const uint8_t *sm, size_t smsz,
    const uint8_t *pk, size_t pk_sz, size_t logn, size_t sig_sz);

// Integration wrappers

// Falcon 512
int PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair(uint8_t *pk, uint8_t *sk) {
    return Zf(keypair)(pk, PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES,
        sk, PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES, 9);
}

int PQCLEAN_FALCON512_CLEAN_crypto_sign_signature(
    uint8_t *sig, size_t *siglen,
    const uint8_t *m, size_t mlen, const uint8_t *sk) {
    return Zf(sign)(sig, siglen, m, mlen, sk,
        PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES, 9);
}

int PQCLEAN_FALCON512_CLEAN_crypto_sign_verify(
    const uint8_t *sig, size_t siglen,
    const uint8_t *m, size_t mlen, const uint8_t *pk) {
    return Zf(verify)(m,mlen,sig,siglen,pk,
        PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES,9,
        PQCLEAN_FALCON512_CLEAN_CRYPTO_BYTES);
}

// Falcon 1024
int PQCLEAN_FALCON1024_CLEAN_crypto_sign_keypair(uint8_t *pk, uint8_t *sk) {
    return Zf(keypair)(pk, PQCLEAN_FALCON1024_CLEAN_CRYPTO_PUBLICKEYBYTES,
        sk, PQCLEAN_FALCON1024_CLEAN_CRYPTO_SECRETKEYBYTES, 10);
}

int PQCLEAN_FALCON1024_CLEAN_crypto_sign_signature(
    uint8_t *sig, size_t *siglen,
    const uint8_t *m, size_t mlen, const uint8_t *sk) {
    return Zf(sign)(sig, siglen, m, mlen, sk,
        PQCLEAN_FALCON1024_CLEAN_CRYPTO_SECRETKEYBYTES, 10);
}

int PQCLEAN_FALCON1024_CLEAN_crypto_sign_verify(
    const uint8_t *sig, size_t siglen,
    const uint8_t *m, size_t mlen, const uint8_t *pk) {
    return Zf(verify)(m,mlen,sig,siglen,pk,
        PQCLEAN_FALCON1024_CLEAN_CRYPTO_PUBLICKEYBYTES,10,
        PQCLEAN_FALCON1024_CLEAN_CRYPTO_BYTES);
}
