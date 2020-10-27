#ifndef PQCLEAN_KYBER1024_AVX2_NTT_H
#define PQCLEAN_KYBER1024_AVX2_NTT_H
#include "consts.h"
#include <stdint.h>

void PQCLEAN_KYBER1024_AVX2_ntt_avx(int16_t *r, const qdata_t *PQCLEAN_KYBER1024_AVX2_qdata);
void PQCLEAN_KYBER1024_AVX2_invntt_avx(int16_t *r, const qdata_t *PQCLEAN_KYBER1024_AVX2_qdata);

void PQCLEAN_KYBER1024_AVX2_nttpack_avx(int16_t *r, const qdata_t *PQCLEAN_KYBER1024_AVX2_qdata);
void PQCLEAN_KYBER1024_AVX2_nttunpack_avx(int16_t *r, const qdata_t *PQCLEAN_KYBER1024_AVX2_qdata);

void PQCLEAN_KYBER1024_AVX2_basemul_avx(int16_t *r,
                                        const int16_t *a,
                                        const int16_t *b,
                                        const qdata_t *PQCLEAN_KYBER1024_AVX2_qdata);
void PQCLEAN_KYBER1024_AVX2_basemul_acc_avx(int16_t *r,
        const int16_t *a,
        const int16_t *b,
        const qdata_t *PQCLEAN_KYBER1024_AVX2_qdata);

void PQCLEAN_KYBER1024_AVX2_ntttobytes_avx(uint8_t *r, const int16_t *a, const qdata_t *PQCLEAN_KYBER1024_AVX2_qdata);
void PQCLEAN_KYBER1024_AVX2_nttfrombytes_avx(int16_t *r, const uint8_t *a, const qdata_t *PQCLEAN_KYBER1024_AVX2_qdata);

#endif
