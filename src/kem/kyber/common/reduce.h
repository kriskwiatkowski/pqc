#ifndef KYBER_REDUCE_H
#define KYBER_REDUCE_H

#include <stdint.h>

// TODO: Remove those once not used
#define PQCLEAN_KYBER512_CLEAN_montgomery_reduce kyber_montgomery_reduce
#define PQCLEAN_KYBER768_CLEAN_montgomery_reduce kyber_montgomery_reduce
#define PQCLEAN_KYBER1024_CLEAN_montgomery_reduce kyber_montgomery_reduce

#define PQCLEAN_KYBER512_CLEAN_barrett_reduce kyber_barrett_reduce
#define PQCLEAN_KYBER768_CLEAN_barrett_reduce kyber_barrett_reduce
#define PQCLEAN_KYBER1024_CLEAN_barrett_reduce kyber_barrett_reduce

#define MONT 2285 // 2^16 mod q
#define QINV 62209 // q^-1 mod 2^16

int16_t kyber_montgomery_reduce(int32_t a);

int16_t kyber_barrett_reduce(int16_t a);

#endif
