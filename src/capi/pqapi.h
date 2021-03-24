#ifndef PQAPI_H_
#define PQAPI_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

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
    uint8_t *sk, uint8_t *pk);

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

#ifdef __cplusplus
}
#endif

#endif
