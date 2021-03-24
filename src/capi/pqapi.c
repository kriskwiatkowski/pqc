#include <stdint.h>
#include <stdbool.h>
#include "pqapi.h"

// PQClean include
#include "sign/rainbow/rainbowV-classic/clean/api.h"
#include "sign/rainbow/rainbowI-classic/clean/api.h"
#include "sign/rainbow/rainbowIII-classic/clean/api.h"
#include "sign/sphincs/sphincs-sha256-192f-simple/clean/api.h"
#include "sign/sphincs/sphincs-sha256-192f-simple/avx2/api.h"
#include "sign/sphincs/sphincs-shake256-256f-simple/clean/api.h"
#include "sign/sphincs/sphincs-shake256-256f-simple/avx2/api.h"
#include "sign/sphincs/sphincs-shake256-192f-robust/clean/api.h"
#include "sign/sphincs/sphincs-shake256-192f-robust/avx2/api.h"
#include "sign/sphincs/sphincs-shake256-128f-simple/clean/api.h"
#include "sign/sphincs/sphincs-shake256-128f-simple/avx2/api.h"
#include "sign/sphincs/sphincs-shake256-256s-simple/clean/api.h"
#include "sign/sphincs/sphincs-shake256-256s-simple/avx2/api.h"
#include "sign/sphincs/sphincs-shake256-128s-simple/clean/api.h"
#include "sign/sphincs/sphincs-shake256-128s-simple/avx2/api.h"
#include "sign/sphincs/sphincs-sha256-128f-robust/clean/api.h"
#include "sign/sphincs/sphincs-sha256-128f-robust/avx2/api.h"
#include "sign/sphincs/sphincs-sha256-192s-robust/clean/api.h"
#include "sign/sphincs/sphincs-sha256-192s-robust/avx2/api.h"
#include "sign/sphincs/sphincs-shake256-128f-robust/clean/api.h"
#include "sign/sphincs/sphincs-shake256-128f-robust/avx2/api.h"
#include "sign/sphincs/sphincs-shake256-128s-robust/clean/api.h"
#include "sign/sphincs/sphincs-shake256-128s-robust/avx2/api.h"
#include "sign/sphincs/sphincs-shake256-256s-robust/clean/api.h"
#include "sign/sphincs/sphincs-shake256-256s-robust/avx2/api.h"
#include "sign/sphincs/sphincs-sha256-192s-simple/clean/api.h"
#include "sign/sphincs/sphincs-sha256-192s-simple/avx2/api.h"
#include "sign/sphincs/sphincs-shake256-192s-simple/clean/api.h"
#include "sign/sphincs/sphincs-shake256-192s-simple/avx2/api.h"
#include "sign/sphincs/sphincs-shake256-192s-robust/clean/api.h"
#include "sign/sphincs/sphincs-shake256-192s-robust/avx2/api.h"
#include "sign/sphincs/sphincs-shake256-192f-simple/clean/api.h"
#include "sign/sphincs/sphincs-shake256-192f-simple/avx2/api.h"
#include "sign/sphincs/sphincs-sha256-256s-simple/clean/api.h"
#include "sign/sphincs/sphincs-sha256-256s-simple/avx2/api.h"
#include "sign/sphincs/sphincs-sha256-128s-simple/clean/api.h"
#include "sign/sphincs/sphincs-sha256-128s-simple/avx2/api.h"
#include "sign/sphincs/sphincs-shake256-256f-robust/clean/api.h"
#include "sign/sphincs/sphincs-shake256-256f-robust/avx2/api.h"
#include "sign/sphincs/sphincs-sha256-256f-robust/clean/api.h"
#include "sign/sphincs/sphincs-sha256-256f-robust/avx2/api.h"
#include "sign/sphincs/sphincs-sha256-256f-simple/clean/api.h"
#include "sign/sphincs/sphincs-sha256-256f-simple/avx2/api.h"
#include "sign/sphincs/sphincs-sha256-256s-robust/clean/api.h"
#include "sign/sphincs/sphincs-sha256-256s-robust/avx2/api.h"
#include "sign/sphincs/sphincs-sha256-128s-robust/clean/api.h"
#include "sign/sphincs/sphincs-sha256-128s-robust/avx2/api.h"
#include "sign/sphincs/sphincs-sha256-128f-simple/clean/api.h"
#include "sign/sphincs/sphincs-sha256-128f-simple/avx2/api.h"
#include "sign/sphincs/sphincs-sha256-192f-robust/clean/api.h"
#include "sign/sphincs/sphincs-sha256-192f-robust/avx2/api.h"
#include "sign/falcon/falcon-1024/clean/api.h"
#include "sign/falcon/falcon-1024/avx2/api.h"
#include "sign/falcon/falcon-512/clean/api.h"
#include "sign/falcon/falcon-512/avx2/api.h"
#include "sign/dilithium/dilithium2/clean/api.h"
#include "sign/dilithium/dilithium2/avx2/api.h"
#include "sign/dilithium/dilithium3/clean/api.h"
#include "sign/dilithium/dilithium3/avx2/api.h"
#include "sign/dilithium/dilithium5/clean/api.h"
#include "sign/dilithium/dilithium5/avx2/api.h"
#include "kem/ntru/ntruhps4096821/clean/api.h"
#include "kem/ntru/ntruhps4096821/avx2/api.h"
#include "kem/ntru/ntruhps2048509/clean/api.h"
#include "kem/ntru/ntruhps2048509/avx2/api.h"
#include "kem/ntru/ntruhrss701/clean/api.h"
#include "kem/ntru/ntruhrss701/avx2/api.h"
#include "kem/ntru/ntruhps2048677/clean/api.h"
#include "kem/ntru/ntruhps2048677/avx2/api.h"
#include "kem/ntru_prime/ntrulpr761/clean/api.h"
#include "kem/ntru_prime/ntrulpr761/avx2/api.h"
#include "kem/ntru_prime/ntrulpr653/clean/api.h"
#include "kem/ntru_prime/ntrulpr653/avx2/api.h"
#include "kem/ntru_prime/ntrulpr857/clean/api.h"
#include "kem/ntru_prime/ntrulpr857/avx2/api.h"
#include "kem/kyber/kyber768/clean/api.h"
#include "kem/kyber/kyber768/avx2/api.h"
#include "kem/kyber/kyber1024/clean/api.h"
#include "kem/kyber/kyber1024/avx2/api.h"
#include "kem/kyber/kyber512/clean/api.h"
#include "kem/kyber/kyber512/avx2/api.h"
#include "kem/mceliece/mceliece460896f/avx/api.h"
#include "kem/mceliece/mceliece460896f/clean/api.h"
#include "kem/mceliece/mceliece8192128/avx/api.h"
#include "kem/mceliece/mceliece8192128/clean/api.h"
#include "kem/mceliece/mceliece6688128f/avx/api.h"
#include "kem/mceliece/mceliece6688128f/clean/api.h"
#include "kem/mceliece/mceliece8192128f/avx/api.h"
#include "kem/mceliece/mceliece8192128f/clean/api.h"
#include "kem/mceliece/mceliece6960119f/avx/api.h"
#include "kem/mceliece/mceliece6960119f/clean/api.h"
#include "kem/mceliece/mceliece460896/avx/api.h"
#include "kem/mceliece/mceliece460896/clean/api.h"
#include "kem/mceliece/mceliece6688128/avx/api.h"
#include "kem/mceliece/mceliece6688128/clean/api.h"
#include "kem/mceliece/mceliece348864f/avx/api.h"
#include "kem/mceliece/mceliece348864f/clean/api.h"
#include "kem/mceliece/mceliece6960119/avx/api.h"
#include "kem/mceliece/mceliece6960119/clean/api.h"
#include "kem/mceliece/mceliece348864/avx/api.h"
#include "kem/mceliece/mceliece348864/clean/api.h"
#include "kem/frodo/frodokem976shake/clean/api.h"
#include "kem/frodo/frodokem1344shake/clean/api.h"
#include "kem/frodo/frodokem640shake/clean/api.h"
#include "kem/saber/lightsaber/clean/api.h"
#include "kem/saber/lightsaber/avx2/api.h"
#include "kem/saber/firesaber/clean/api.h"
#include "kem/saber/firesaber/avx2/api.h"
#include "kem/saber/saber/clean/api.h"
#include "kem/saber/saber/avx2/api.h"

// not proud of this thingy
#define OPT_VERSION _CLEAN_

// Helper to stringify constants
#define STR(x) STR_(x)
#define STR_(x) #x

/* Concatenate tokens X and Y. Can be done by the "##" operator in
 * simple cases, but has some side effects in more complicated cases.
 */
#define GLUE(a, b) GLUE_(a, b)
#define GLUE_(a, b) a##b

// Returns prefix defined by PQClean, depending
// on OPT_VERSION setting.
// Something like: "PQCLEAN_KYBER512_CLEAN_"
#define A(x)                    \
    GLUE(PQCLEAN_,              \
        GLUE(x, OPT_VERSION))   \

#define PQC_PUB_KEY_BSZ(x) GLUE(A(x), CRYPTO_PUBLICKEYBYTES)
#define PQC_PRV_KEY_BSZ(x) GLUE(A(x), CRYPTO_SECRETKEYBYTES)
#define PQC_KEM_BSZ(x) GLUE(A(x), CRYPTO_BYTES)
#define PQC_SIGN_BSZ(x) GLUE(A(x), CRYPTO_BYTES)
#define PQC_CT_BSZ(x) GLUE(A(x), CRYPTO_CIPHERTEXTBYTES)
#define PQC_NAME(x) GLUE(A(x), CRYPTO_ALGNAME)
#define PQC_FN_KEM_KEYGEN(x) GLUE(A(x), crypto_kem_keypair)
#define PQC_FN_SIG_KEYGEN(x) GLUE(A(x), crypto_sign_keypair)
#define PQC_FN_ENCAPS(x) GLUE(A(x), crypto_kem_enc)
#define PQC_FN_DECAPS(x) GLUE(A(x), crypto_kem_dec)
#define PQC_FN_SIGN(x) GLUE(A(x), crypto_sign_signature)
#define PQC_FN_VERIFY(x) GLUE(A(x), crypto_sign_verify)

#define REG_ALG(ID)                     \
{                                       \
    .alg_id = ID,                       \
    .alg_name = STR(ID),                \
    .prv_key_bsz = PQC_PRV_KEY_BSZ(ID), \
    .pub_key_bsz = PQC_PUB_KEY_BSZ(ID), \
}

// Macro magic needed to initialize parameters for a scheme
#define REG_KEM(ID)                   \
{                                     \
    .p = REG_ALG(ID),                 \
    .p.keygen = PQC_FN_KEM_KEYGEN(ID),\
    .ciphertext_bsz = PQC_CT_BSZ(ID), \
    .secret_bsz = PQC_KEM_BSZ(ID),    \
    .encapsulate = PQC_FN_ENCAPS(ID), \
    .decapsulate = PQC_FN_DECAPS(ID), \
},

// Macro magic needed to initialize parameters for a scheme
#define REG_SIG(ID)                   \
{                                     \
    .p = REG_ALG(ID),                 \
    .p.keygen = PQC_FN_SIG_KEYGEN(ID),\
    .sign_bsz = PQC_SIGN_BSZ(ID),     \
    .sign = PQC_FN_SIGN(ID),          \
    .verify = PQC_FN_VERIFY(ID),      \
},

// Registers supported KEMs
const kem_params_t kems[] = {
    PQC_SUPPORTED_KEMS(REG_KEM)
};

// Registers supported signatures
const sig_params_t sigs[] = {
    PQC_SUPPORTED_SIGS(REG_SIG)
};

const params_t *pqc_kem_alg_by_id(uint8_t id) {
    int i;
    for(i=0; i<PQC_ALG_KEM_MAX; i++) {
        if (kems[i].p.alg_id == id) {
            return (params_t*)&kems[i];
        }
    }
    return 0;
}

const params_t *pqc_sig_alg_by_id(uint8_t id) {
    int i;
    for(i=0; i<PQC_ALG_SIG_MAX; i++) {
        if (sigs[i].p.alg_id == id) {
            return (params_t*)&sigs[i];
        }
    }
    return 0;
}

bool pqc_keygen(const params_t *p, uint8_t *sk, uint8_t *pk) {
    return !p->keygen(sk, pk);
}

bool pqc_kem_encapsulate(const params_t *p, uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    return !((kem_params_t*)p)->encapsulate(ct, ss, pk);
}

bool pqc_kem_decapsulate(const params_t *p, uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    return !((kem_params_t*)p)->decapsulate(ss, ct, sk);
}

bool pqc_sig_create(
    const params_t *p, uint8_t *sig, uint64_t *siglen, const uint8_t *m, uint64_t mlen, const uint8_t *sk) {
    return !((sig_params_t *)p)->sign(sig, siglen, m, mlen, sk);
}

bool pqc_sig_verify(
    const params_t *p, const uint8_t *sig, uint64_t siglen, const uint8_t *m, uint64_t mlen, const uint8_t *pk) {
    return !((sig_params_t *)p)->verify(sig, siglen, m, mlen, pk);
}
