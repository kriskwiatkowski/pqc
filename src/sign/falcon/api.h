#ifndef PQCLEAN_FALCON_CLEAN_API_H
#define PQCLEAN_FALCON_CLEAN_API_H

#include <stddef.h>
#include <stdint.h>

#define PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES 897
#define PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES 1281
#define PQCLEAN_FALCON512_CLEAN_CRYPTO_BYTES 690
#define PQCLEAN_FALCON512_CLEAN_CRYPTO_ALGNAME "Falcon512"

#define PQCLEAN_FALCON1024_CLEAN_CRYPTO_PUBLICKEYBYTES 1793
#define PQCLEAN_FALCON1024_CLEAN_CRYPTO_SECRETKEYBYTES 2305
#define PQCLEAN_FALCON1024_CLEAN_CRYPTO_BYTES 1330
#define PQCLEAN_FALCON1024_CLEAN_CRYPTO_ALGNAME "Falcon1024"

int PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair(uint8_t *pk, uint8_t *sk);

int PQCLEAN_FALCON512_CLEAN_crypto_sign_signature(
    uint8_t *sig, size_t *siglen,
    const uint8_t *m, size_t mlen, const uint8_t *sk);

int PQCLEAN_FALCON512_CLEAN_crypto_sign_verify(
    const uint8_t *sig, size_t siglen,
    const uint8_t *m, size_t mlen, const uint8_t *pk);

int PQCLEAN_FALCON1024_CLEAN_crypto_sign_keypair(uint8_t *pk, uint8_t *sk);

int PQCLEAN_FALCON1024_CLEAN_crypto_sign_signature(
    uint8_t *sig, size_t *siglen,
    const uint8_t *m, size_t mlen, const uint8_t *sk);

int PQCLEAN_FALCON1024_CLEAN_crypto_sign_verify(
    const uint8_t *sig, size_t siglen,
    const uint8_t *m, size_t mlen, const uint8_t *pk);

#endif
