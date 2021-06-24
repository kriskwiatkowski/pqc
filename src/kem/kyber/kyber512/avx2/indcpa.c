#include "align.h"
#include "cbd.h"
#include "indcpa.h"
#include "ntt.h"
#include "params.h"
#include "poly.h"
#include "polyvec.h"
#include "randombytes.h"
#include "rejsample.h"
#include "symmetric.h"
#include <immintrin.h>
#include <stddef.h>
#include <stdint.h>

/*************************************************
* Name:        pack_pk
*
* Description: Serialize the public key as concatenation of the
*              serialized vector of polynomials pk and the
*              public seed used to generate the matrix A.
*              The polynomial coefficients in pk are assumed to
*              lie in the invertal [0,q], i.e. pk must be reduced
*              by PQCLEAN_KYBER512_AVX2_polyvec_reduce().
*
* Arguments:   uint8_t *r: pointer to the output serialized public key
*              polyvec *pk: pointer to the input public-key polyvec
*              const uint8_t *seed: pointer to the input public seed
**************************************************/
static void pack_pk(uint8_t r[KYBER_INDCPA_PUBLICKEYBYTES],
                    polyvec *pk,
                    const uint8_t seed[KYBER_SYMBYTES]) {
    size_t i;
    PQCLEAN_KYBER512_AVX2_polyvec_tobytes(r, pk);
    for (i = 0; i < KYBER_SYMBYTES; i++) {
        r[i + KYBER_POLYVECBYTES] = seed[i];
    }
}

/*************************************************
* Name:        unpack_pk
*
* Description: De-serialize public key from a byte array;
*              approximate inverse of pack_pk
*
* Arguments:   - polyvec *pk: pointer to output public-key polynomial vector
*              - uint8_t *seed: pointer to output seed to generate matrix A
*              - const uint8_t *packedpk: pointer to input serialized public key
**************************************************/
static void unpack_pk(polyvec *pk,
                      uint8_t seed[KYBER_SYMBYTES],
                      const uint8_t packedpk[KYBER_INDCPA_PUBLICKEYBYTES]) {
    size_t i;
    PQCLEAN_KYBER512_AVX2_polyvec_frombytes(pk, packedpk);
    for (i = 0; i < KYBER_SYMBYTES; i++) {
        seed[i] = packedpk[i + KYBER_POLYVECBYTES];
    }
}

/*************************************************
* Name:        pack_sk
*
* Description: Serialize the secret key.
*              The polynomial coefficients in sk are assumed to
*              lie in the invertal [0,q], i.e. sk must be reduced
*              by PQCLEAN_KYBER512_AVX2_polyvec_reduce().
*
* Arguments:   - uint8_t *r: pointer to output serialized secret key
*              - polyvec *sk: pointer to input vector of polynomials (secret key)
**************************************************/
static void pack_sk(uint8_t r[KYBER_INDCPA_SECRETKEYBYTES], polyvec *sk) {
    PQCLEAN_KYBER512_AVX2_polyvec_tobytes(r, sk);
}

/*************************************************
* Name:        unpack_sk
*
* Description: De-serialize the secret key; inverse of pack_sk
*
* Arguments:   - polyvec *sk: pointer to output vector of polynomials (secret key)
*              - const uint8_t *packedsk: pointer to input serialized secret key
**************************************************/
static void unpack_sk(polyvec *sk, const uint8_t packedsk[KYBER_INDCPA_SECRETKEYBYTES]) {
    PQCLEAN_KYBER512_AVX2_polyvec_frombytes(sk, packedsk);
}

/*************************************************
* Name:        pack_ciphertext
*
* Description: Serialize the ciphertext as concatenation of the
*              compressed and serialized vector of polynomials b
*              and the compressed and serialized polynomial v.
*              The polynomial coefficients in b and v are assumed to
*              lie in the invertal [0,q], i.e. b and v must be reduced
*              by PQCLEAN_KYBER512_AVX2_polyvec_reduce() and PQCLEAN_KYBER512_AVX2_poly_reduce(), respectively.
*
* Arguments:   uint8_t *r: pointer to the output serialized ciphertext
*              poly *pk: pointer to the input vector of polynomials b
*              poly *v: pointer to the input polynomial v
**************************************************/
static void pack_ciphertext(uint8_t r[KYBER_INDCPA_BYTES], polyvec *b, poly *v) {
    PQCLEAN_KYBER512_AVX2_polyvec_compress(r, b);
    PQCLEAN_KYBER512_AVX2_poly_compress(r + KYBER_POLYVECCOMPRESSEDBYTES, v);
}

/*************************************************
* Name:        unpack_ciphertext
*
* Description: De-serialize and decompress ciphertext from a byte array;
*              approximate inverse of pack_ciphertext
*
* Arguments:   - polyvec *b: pointer to the output vector of polynomials b
*              - poly *v: pointer to the output polynomial v
*              - const uint8_t *c: pointer to the input serialized ciphertext
**************************************************/
static void unpack_ciphertext(polyvec *b, poly *v, const uint8_t c[KYBER_INDCPA_BYTES]) {
    PQCLEAN_KYBER512_AVX2_polyvec_decompress(b, c);
    PQCLEAN_KYBER512_AVX2_poly_decompress(v, c + KYBER_POLYVECCOMPRESSEDBYTES);
}

/*************************************************
* Name:        rej_uniform
*
* Description: Run rejection sampling on uniform random bytes to generate
*              uniform random integers mod q
*
* Arguments:   - int16_t *r: pointer to output array
*              - unsigned int len: requested number of 16-bit integers (uniform mod q)
*              - const uint8_t *buf: pointer to input buffer (assumed to be uniformly random bytes)
*              - unsigned int buflen: length of input buffer in bytes
*
* Returns number of sampled 16-bit integers (at most len)
**************************************************/
static unsigned int rej_uniform(int16_t *r,
                                unsigned int len,
                                const uint8_t *buf,
                                unsigned int buflen) {
    unsigned int ctr, pos;
    uint16_t val0, val1;

    ctr = pos = 0;
    while (ctr < len && pos + 3 <= buflen) {
        val0 = ((buf[pos + 0] >> 0) | ((uint16_t)buf[pos + 1] << 8)) & 0xFFF;
        val1 = ((buf[pos + 1] >> 4) | ((uint16_t)buf[pos + 2] << 4)) & 0xFFF;
        pos += 3;

        if (val0 < KYBER_Q) {
            r[ctr++] = val0;
        }
        if (ctr < len && val1 < KYBER_Q) {
            r[ctr++] = val1;
        }
    }

    return ctr;
}

#define gen_a(A,B)  PQCLEAN_KYBER512_AVX2_gen_matrix(A,B,0)
#define gen_at(A,B) PQCLEAN_KYBER512_AVX2_gen_matrix(A,B,1)

/*************************************************
* Name:        PQCLEAN_KYBER512_AVX2_gen_matrix
*
* Description: Deterministically generate matrix A (or the transpose of A)
*              from a seed. Entries of the matrix are polynomials that look
*              uniformly random. Performs rejection sampling on output of
*              a XOF
*
* Arguments:   - polyvec *a: pointer to ouptput matrix A
*              - const uint8_t *seed: pointer to input seed
*              - int transposed: boolean deciding whether A or A^T is generated
**************************************************/
void PQCLEAN_KYBER512_AVX2_gen_matrix(polyvec *a, const uint8_t seed[32], int transposed) {
    unsigned int ctr0, ctr1, ctr2, ctr3;
    ALIGNED_UINT8(REJ_UNIFORM_AVX_NBLOCKS * SHAKE128_RATE) buf[4];
    __m256i f;
    keccakx4_state state;

    f = _mm256_loadu_si256((__m256i *)seed);
    _mm256_store_si256(buf[0].vec, f);
    _mm256_store_si256(buf[1].vec, f);
    _mm256_store_si256(buf[2].vec, f);
    _mm256_store_si256(buf[3].vec, f);

    if (transposed) {
        buf[0].coeffs[32] = 0;
        buf[0].coeffs[33] = 0;
        buf[1].coeffs[32] = 0;
        buf[1].coeffs[33] = 1;
        buf[2].coeffs[32] = 1;
        buf[2].coeffs[33] = 0;
        buf[3].coeffs[32] = 1;
        buf[3].coeffs[33] = 1;
    } else {
        buf[0].coeffs[32] = 0;
        buf[0].coeffs[33] = 0;
        buf[1].coeffs[32] = 1;
        buf[1].coeffs[33] = 0;
        buf[2].coeffs[32] = 0;
        buf[2].coeffs[33] = 1;
        buf[3].coeffs[32] = 1;
        buf[3].coeffs[33] = 1;
    }

    PQCLEAN_KYBER512_AVX2_shake128x4_absorb_once(&state, buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, 34);
    PQCLEAN_KYBER512_AVX2_shake128x4_squeezeblocks(buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, REJ_UNIFORM_AVX_NBLOCKS, &state);

    ctr0 = PQCLEAN_KYBER512_AVX2_rej_uniform_avx(a[0].vec[0].coeffs, buf[0].coeffs);
    ctr1 = PQCLEAN_KYBER512_AVX2_rej_uniform_avx(a[0].vec[1].coeffs, buf[1].coeffs);
    ctr2 = PQCLEAN_KYBER512_AVX2_rej_uniform_avx(a[1].vec[0].coeffs, buf[2].coeffs);
    ctr3 = PQCLEAN_KYBER512_AVX2_rej_uniform_avx(a[1].vec[1].coeffs, buf[3].coeffs);

    while (ctr0 < KYBER_N || ctr1 < KYBER_N || ctr2 < KYBER_N || ctr3 < KYBER_N) {
        PQCLEAN_KYBER512_AVX2_shake128x4_squeezeblocks(buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, 1, &state);

        ctr0 += rej_uniform(a[0].vec[0].coeffs + ctr0, KYBER_N - ctr0, buf[0].coeffs, SHAKE128_RATE);
        ctr1 += rej_uniform(a[0].vec[1].coeffs + ctr1, KYBER_N - ctr1, buf[1].coeffs, SHAKE128_RATE);
        ctr2 += rej_uniform(a[1].vec[0].coeffs + ctr2, KYBER_N - ctr2, buf[2].coeffs, SHAKE128_RATE);
        ctr3 += rej_uniform(a[1].vec[1].coeffs + ctr3, KYBER_N - ctr3, buf[3].coeffs, SHAKE128_RATE);
    }

    PQCLEAN_KYBER512_AVX2_poly_nttunpack(&a[0].vec[0]);
    PQCLEAN_KYBER512_AVX2_poly_nttunpack(&a[0].vec[1]);
    PQCLEAN_KYBER512_AVX2_poly_nttunpack(&a[1].vec[0]);
    PQCLEAN_KYBER512_AVX2_poly_nttunpack(&a[1].vec[1]);
}

/*************************************************
* Name:        PQCLEAN_KYBER512_AVX2_indcpa_keypair
*
* Description: Generates public and private key for the CPA-secure
*              public-key encryption scheme underlying Kyber
*
* Arguments:   - uint8_t *pk: pointer to output public key
*                             (of length KYBER_INDCPA_PUBLICKEYBYTES bytes)
*              - uint8_t *sk: pointer to output private key
                              (of length KYBER_INDCPA_SECRETKEYBYTES bytes)
**************************************************/
void PQCLEAN_KYBER512_AVX2_indcpa_keypair(uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
        uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES]) {
    unsigned int i;
    uint8_t buf[2 * KYBER_SYMBYTES];
    const uint8_t *publicseed = buf;
    const uint8_t *noiseseed = buf + KYBER_SYMBYTES;
    polyvec a[KYBER_K], e, pkpv, skpv;

    randombytes(buf, KYBER_SYMBYTES);
    hash_g(buf, buf, KYBER_SYMBYTES);

    gen_a(a, publicseed);

    PQCLEAN_KYBER512_AVX2_poly_getnoise_eta1_4x(skpv.vec + 0, skpv.vec + 1, e.vec + 0, e.vec + 1, noiseseed, 0, 1, 2, 3);

    PQCLEAN_KYBER512_AVX2_polyvec_ntt(&skpv);
    PQCLEAN_KYBER512_AVX2_polyvec_reduce(&skpv);
    PQCLEAN_KYBER512_AVX2_polyvec_ntt(&e);

    // matrix-vector multiplication
    for (i = 0; i < KYBER_K; i++) {
        PQCLEAN_KYBER512_AVX2_polyvec_basemul_acc_montgomery(&pkpv.vec[i], &a[i], &skpv);
        PQCLEAN_KYBER512_AVX2_poly_tomont(&pkpv.vec[i]);
    }

    PQCLEAN_KYBER512_AVX2_polyvec_add(&pkpv, &pkpv, &e);
    PQCLEAN_KYBER512_AVX2_polyvec_reduce(&pkpv);

    pack_sk(sk, &skpv);
    pack_pk(pk, &pkpv, publicseed);
}

/*************************************************
* Name:        PQCLEAN_KYBER512_AVX2_indcpa_enc
*
* Description: Encryption function of the CPA-secure
*              public-key encryption scheme underlying Kyber.
*
* Arguments:   - uint8_t *c: pointer to output ciphertext
*                            (of length KYBER_INDCPA_BYTES bytes)
*              - const uint8_t *m: pointer to input message
*                                  (of length KYBER_INDCPA_MSGBYTES bytes)
*              - const uint8_t *pk: pointer to input public key
*                                   (of length KYBER_INDCPA_PUBLICKEYBYTES)
*              - const uint8_t *coins: pointer to input random coins used as seed
*                                      (of length KYBER_SYMBYTES) to deterministically
*                                      generate all randomness
**************************************************/
void PQCLEAN_KYBER512_AVX2_indcpa_enc(uint8_t c[KYBER_INDCPA_BYTES],
                                      const uint8_t m[KYBER_INDCPA_MSGBYTES],
                                      const uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                                      const uint8_t coins[KYBER_SYMBYTES]) {
    unsigned int i;
    uint8_t seed[KYBER_SYMBYTES];
    polyvec sp, pkpv, ep, at[KYBER_K], b = {0};
    poly v, k, epp;

    unpack_pk(&pkpv, seed, pk);
    PQCLEAN_KYBER512_AVX2_poly_frommsg(&k, m);
    gen_at(at, seed);

    PQCLEAN_KYBER512_AVX2_poly_getnoise_eta1122_4x(sp.vec + 0, sp.vec + 1, ep.vec + 0, ep.vec + 1, coins, 0, 1, 2, 3);
    PQCLEAN_KYBER512_AVX2_poly_getnoise_eta2(&epp, coins, 4);

    PQCLEAN_KYBER512_AVX2_polyvec_ntt(&sp);

    // matrix-vector multiplication
    for (i = 0; i < KYBER_K; i++) {
        PQCLEAN_KYBER512_AVX2_polyvec_basemul_acc_montgomery(&b.vec[i], &at[i], &sp);
    }
    PQCLEAN_KYBER512_AVX2_polyvec_basemul_acc_montgomery(&v, &pkpv, &sp);

    PQCLEAN_KYBER512_AVX2_polyvec_invntt_tomont(&b);
    PQCLEAN_KYBER512_AVX2_poly_invntt_tomont(&v);

    PQCLEAN_KYBER512_AVX2_polyvec_add(&b, &b, &ep);
    PQCLEAN_KYBER512_AVX2_poly_add(&v, &v, &epp);
    PQCLEAN_KYBER512_AVX2_poly_add(&v, &v, &k);
    PQCLEAN_KYBER512_AVX2_polyvec_reduce(&b);
    PQCLEAN_KYBER512_AVX2_poly_reduce(&v);

    pack_ciphertext(c, &b, &v);
}

/*************************************************
* Name:        PQCLEAN_KYBER512_AVX2_indcpa_dec
*
* Description: Decryption function of the CPA-secure
*              public-key encryption scheme underlying Kyber.
*
* Arguments:   - uint8_t *m: pointer to output decrypted message
*                            (of length KYBER_INDCPA_MSGBYTES)
*              - const uint8_t *c: pointer to input ciphertext
*                                  (of length KYBER_INDCPA_BYTES)
*              - const uint8_t *sk: pointer to input secret key
*                                   (of length KYBER_INDCPA_SECRETKEYBYTES)
**************************************************/
void PQCLEAN_KYBER512_AVX2_indcpa_dec(uint8_t m[KYBER_INDCPA_MSGBYTES],
                                      const uint8_t c[KYBER_INDCPA_BYTES],
                                      const uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES]) {
    polyvec b, skpv;
    poly v, mp;

    unpack_ciphertext(&b, &v, c);
    unpack_sk(&skpv, sk);

    PQCLEAN_KYBER512_AVX2_polyvec_ntt(&b);
    PQCLEAN_KYBER512_AVX2_polyvec_basemul_acc_montgomery(&mp, &skpv, &b);
    PQCLEAN_KYBER512_AVX2_poly_invntt_tomont(&mp);

    PQCLEAN_KYBER512_AVX2_poly_sub(&mp, &v, &mp);
    PQCLEAN_KYBER512_AVX2_poly_reduce(&mp);

    PQCLEAN_KYBER512_AVX2_poly_tomsg(m, &mp);
}
