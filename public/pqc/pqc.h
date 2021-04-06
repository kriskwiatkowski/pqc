#ifndef PQAPI_H_
#define PQAPI_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

// defines supported signature algorithm list
#define PQC_SUPPORTED_SIGS(_)    \
    _(DILITHIUM2)                \
    _(DILITHIUM3)                \
    _(DILITHIUM5)                \
    _(FALCON1024)                \
    _(FALCON512)                 \
    _(RAINBOWVCLASSIC)           \
    _(RAINBOWICLASSIC)           \
    _(RAINBOWIIICLASSIC)         \
    _(SPHINCSSHA256192FSIMPLE)   \
    _(SPHINCSSHAKE256256FSIMPLE) \
    _(SPHINCSSHAKE256192FROBUST) \
    _(SPHINCSSHAKE256128FSIMPLE) \
    _(SPHINCSSHAKE256256SSIMPLE) \
    _(SPHINCSSHAKE256128SSIMPLE) \
    _(SPHINCSSHA256128FROBUST)   \
    _(SPHINCSSHA256192SROBUST)   \
    _(SPHINCSSHAKE256128FROBUST) \
    _(SPHINCSSHAKE256128SROBUST) \
    _(SPHINCSSHAKE256256SROBUST) \
    _(SPHINCSSHA256192SSIMPLE)   \
    _(SPHINCSSHAKE256192SSIMPLE) \
    _(SPHINCSSHAKE256192SROBUST) \
    _(SPHINCSSHAKE256192FSIMPLE) \
    _(SPHINCSSHA256256SSIMPLE)   \
    _(SPHINCSSHA256128SSIMPLE)   \
    _(SPHINCSSHAKE256256FROBUST) \
    _(SPHINCSSHA256256FROBUST)   \
    _(SPHINCSSHA256256FSIMPLE)   \
    _(SPHINCSSHA256256SROBUST)   \
    _(SPHINCSSHA256128SROBUST)   \
    _(SPHINCSSHA256128FSIMPLE)   \
    _(SPHINCSSHA256192FROBUST)

// defines supported kem algorithm list
#define PQC_SUPPORTED_KEMS(_)\
    _(FRODOKEM976SHAKE)  \
    _(FRODOKEM1344SHAKE) \
    _(FRODOKEM640SHAKE)  \
    _(KYBER768)          \
    _(KYBER1024)         \
    _(KYBER512)          \
    _(NTRUHPS4096821)    \
    _(NTRUHPS2048509)    \
    _(NTRUHRSS701)       \
    _(NTRUHPS2048677)    \
    _(NTRULPR761)        \
    _(NTRULPR653)        \
    _(NTRULPR857)        \
    _(LIGHTSABER)        \
    _(FIRESABER)         \
    _(SABER)             \
    _(HQCRMRS128)        \
    _(HQCRMRS192)        \
    _(HQCRMRS256)        \
    _(SIKE434)

// Defines IDs for each algorithm. The
// PQC_ALG_SIG/KEM_MAX indicates number
// of KEM and signature schemes supported.
#define DEFNUM(N) N,
enum { PQC_SUPPORTED_SIGS(DEFNUM) PQC_ALG_SIG_MAX };
enum { PQC_SUPPORTED_KEMS(DEFNUM) PQC_ALG_KEM_MAX };
#undef DEFNUM

// Parameters of the scheme
typedef struct params_t {
    const uint8_t alg_id;
    const char* alg_name;
    const uint32_t prv_key_bsz;
    const uint32_t pub_key_bsz;
    const bool is_kem;

    int (*keygen)(uint8_t *sk, uint8_t *pk);
} params_t;

typedef struct kem_params_t {
    params_t p;
    const uint32_t ciphertext_bsz;
    const uint32_t secret_bsz;

    int (*encapsulate)(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
    int (*decapsulate)(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
} kem_params_t;

typedef struct sig_params_t {
    params_t p;
    const uint32_t sign_bsz;
    int (*sign)(uint8_t *sig, uint64_t *siglen, const uint8_t *m, uint64_t mlen, const uint8_t *sk);
    int (*verify)(const uint8_t *sig, uint64_t siglen, const uint8_t *m, uint64_t mlen, const uint8_t *pk);
} sig_params_t;

inline uint32_t ciphertext_bsz(const params_t *p) {
    return ((kem_params_t *)p)->ciphertext_bsz;
}

inline uint32_t shared_secret_bsz(const params_t *p) {
    return ((kem_params_t *)p)->secret_bsz;
}

inline uint32_t signature_bsz(const params_t *p) {
    return ((sig_params_t *)p)->sign_bsz;
}

inline uint32_t public_key_bsz(const params_t *p) {
    return p->pub_key_bsz;
}

inline uint32_t private_key_bsz(const params_t *p) {
    return p->prv_key_bsz;
}

bool pqc_keygen(
    const params_t *p,
    uint8_t *pk, uint8_t *sk);

bool pqc_kem_encapsulate(
    const params_t *p,
    uint8_t *ct, uint8_t *ss,
    const uint8_t *pk);

bool pqc_kem_decapsulate(
    const params_t *p,
    uint8_t *ss, const uint8_t *ct,
    const uint8_t *sk);

bool pqc_sig_create(
    const params_t *p,
    uint8_t *sig, uint64_t *siglen,
    const uint8_t *m, uint64_t mlen,
    const uint8_t *sk);

bool pqc_sig_verify(
    const params_t *p,
    const uint8_t *sig, uint64_t siglen,
    const uint8_t *m, uint64_t mlen,
    const uint8_t *pk);


const params_t *pqc_kem_alg_by_id(uint8_t id);
const params_t *pqc_sig_alg_by_id(uint8_t id);

#ifdef __cplusplus
}
#endif

#endif
