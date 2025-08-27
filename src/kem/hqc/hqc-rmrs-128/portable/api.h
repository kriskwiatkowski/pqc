#ifndef PQC_HQC128_PORTABLE_API_H
#define PQC_HQC128_PORTABLE_API_H
/**
 * @file api.h
 * @brief NIST KEM API used by the HQC_KEM IND-CCA2 scheme
 */

#define PQC_HQC128_PORTABLE_CRYPTO_ALGNAME                      "HQC-RMRS-128"

#define PQC_HQC128_PORTABLE_CRYPTO_SECRETKEYBYTES               2289
#define PQC_HQC128_PORTABLE_CRYPTO_PUBLICKEYBYTES               2249
#define PQC_HQC128_PORTABLE_CRYPTO_BYTES                        64
#define PQC_HQC128_PORTABLE_CRYPTO_CIPHERTEXTBYTES              4481

// As a technicality, the public key is appended to the secret key in order to respect the NIST API.
// Without this constraint, PQC_HQC128_PORTABLE_CRYPTO_SECRETKEYBYTES would be defined as 32

int PQC_HQC128_PORTABLE_crypto_kem_keypair(unsigned char *pk, unsigned char *sk);

int PQC_HQC128_PORTABLE_crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);

int PQC_HQC128_PORTABLE_crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);

// Compatibility macros for legacy PQCLEAN naming
#define PQCLEAN_HQCRMRS128_CLEAN_CRYPTO_ALGNAME             PQC_HQC128_PORTABLE_CRYPTO_ALGNAME
#define PQCLEAN_HQCRMRS128_CLEAN_CRYPTO_SECRETKEYBYTES      PQC_HQC128_PORTABLE_CRYPTO_SECRETKEYBYTES
#define PQCLEAN_HQCRMRS128_CLEAN_CRYPTO_PUBLICKEYBYTES      PQC_HQC128_PORTABLE_CRYPTO_PUBLICKEYBYTES
#define PQCLEAN_HQCRMRS128_CLEAN_CRYPTO_BYTES               PQC_HQC128_PORTABLE_CRYPTO_BYTES
#define PQCLEAN_HQCRMRS128_CLEAN_CRYPTO_CIPHERTEXTBYTES     PQC_HQC128_PORTABLE_CRYPTO_CIPHERTEXTBYTES
#define PQCLEAN_HQCRMRS128_CLEAN_crypto_kem_keypair         PQC_HQC128_PORTABLE_crypto_kem_keypair
#define PQCLEAN_HQCRMRS128_CLEAN_crypto_kem_enc             PQC_HQC128_PORTABLE_crypto_kem_enc
#define PQCLEAN_HQCRMRS128_CLEAN_crypto_kem_dec             PQC_HQC128_PORTABLE_crypto_kem_dec

#endif
