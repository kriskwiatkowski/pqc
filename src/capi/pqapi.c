#include <stdint.h>
#include <stdbool.h>
#include <pqc/pqc.h>
#include <cpuinfo_x86.h>

#include "schemes.h"

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

// Contains capabilities on x86 CPU on which implementation is running
X86Features CPU_CAPS;

const X86Features * const get_cpu_caps(void) {
    return &CPU_CAPS;
}

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

bool pqc_keygen(const params_t *p,
    uint8_t *pk, uint8_t *sk) {
    return !p->keygen(pk, sk);
}

bool pqc_kem_encapsulate(const params_t *p,
    uint8_t *ct, uint8_t *ss,
    const uint8_t *pk) {
    return !((kem_params_t*)p)->encapsulate(ct, ss, pk);
}

bool pqc_kem_decapsulate(const params_t *p,
    uint8_t *ss, const uint8_t *ct,
    const uint8_t *sk) {
    return !((kem_params_t*)p)->decapsulate(ss, ct, sk);
}

bool pqc_sig_create(const params_t *p,
    uint8_t *sig, uint64_t *siglen,
    const uint8_t *m, uint64_t mlen,
    const uint8_t *sk) {
    return !((sig_params_t *)p)->sign(sig, siglen, m, mlen, sk);
}

bool pqc_sig_verify(const params_t *p,
    const uint8_t *sig, uint64_t siglen,
    const uint8_t *m, uint64_t mlen,
    const uint8_t *pk) {
    return !((sig_params_t *)p)->verify(sig, siglen, m, mlen, pk);
}

void static_initialization(void) __attribute__((constructor));
void static_initialization(void) {
    CPU_CAPS = GetX86Info().features;
}
