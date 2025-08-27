#ifndef FFT_H
#define FFT_H


/**
 * @file fft.h
 * Header file of fft.c
 */

#include <stddef.h>
#include <stdint.h>

void PQC_HQC256_fft(uint16_t *w, const uint16_t *f, size_t f_coeffs);

void PQC_HQC256_fft_retrieve_error_poly(uint8_t *error, const uint16_t *w);


#endif
