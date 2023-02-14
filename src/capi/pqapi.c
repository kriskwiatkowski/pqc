#include <stdint.h>
#include <stdbool.h>
#include <pqc/pqc.h>
#include <common/utils.h>

#include "schemes.h"

// not proud of this thingy
#define OPT_VERSION _CLEAN_

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

#define REG_ALG(PFX,ID)                 \
{                                       \
    .alg_id = GLUE(PFX,ID),             \
    .alg_name = STR(ID),                \
    .prv_key_bsz = PQC_PRV_KEY_BSZ(ID), \
    .pub_key_bsz = PQC_PUB_KEY_BSZ(ID), \
}

// Macro magic needed to initialize parameters for a scheme
#define REG_KEM(ID)                   \
{                                     \
    .p = REG_ALG(PQC_ALG_KEM_,ID),    \
    .p.keygen = PQC_FN_KEM_KEYGEN(ID),\
    .ciphertext_bsz = PQC_CT_BSZ(ID), \
    .secret_bsz = PQC_KEM_BSZ(ID),    \
    .encapsulate = PQC_FN_ENCAPS(ID), \
    .decapsulate = PQC_FN_DECAPS(ID), \
},

// Macro magic needed to initialize parameters for a scheme
#define REG_SIG(ID)                   \
{                                     \
    .p = REG_ALG(PQC_ALG_SIG_,ID),    \
    .p.keygen = PQC_FN_SIG_KEYGEN(ID),\
    .sign_bsz = PQC_SIGN_BSZ(ID),     \
    .sign = PQC_FN_SIGN(ID),          \
    .verify = PQC_FN_VERIFY(ID),      \
},

// Registers supported KEMs
const pqc_kem_ctx_t kems[] = {
    PQC_SUPPORTED_KEMS(REG_KEM)
};

// Registers supported signatures
const pqc_sig_ctx_t sigs[] = {
    PQC_SUPPORTED_SIGS(REG_SIG)
};

const pqc_ctx_t *pqc_kem_alg_by_id(uint8_t id) {
    int i;
    for(i=0; i<PQC_ALG_KEM_MAX; i++) {
        if (kems[i].p.alg_id == id) {
            return (pqc_ctx_t*)&kems[i];
        }
    }
    return 0;
}

const pqc_ctx_t *pqc_sig_alg_by_id(uint8_t id) {
    int i;
    for(i=0; i<PQC_ALG_SIG_MAX; i++) {
        if (sigs[i].p.alg_id == id) {
            return (pqc_ctx_t*)&sigs[i];
        }
    }
    return 0;
}

bool pqc_keygen(const pqc_ctx_t *p,
    uint8_t *pk, uint8_t *sk) {
    return !p->keygen(pk, sk);
}

bool pqc_kem_encapsulate(const pqc_ctx_t *p,
    uint8_t *ct, uint8_t *ss,
    const uint8_t *pk) {
    return !((pqc_kem_ctx_t*)p)->encapsulate(ct, ss, pk);
}

bool pqc_kem_decapsulate(const pqc_ctx_t *p,
    uint8_t *ss, const uint8_t *ct,
    const uint8_t *sk) {
    return !((pqc_kem_ctx_t*)p)->decapsulate(ss, ct, sk);
}

bool pqc_sig_create(const pqc_ctx_t *p,
    uint8_t *sig, uint64_t *siglen,
    const uint8_t *m, uint64_t mlen,
    const uint8_t *sk) {
    return !((pqc_sig_ctx_t *)p)->sign(sig, siglen, m, mlen, sk);
}

bool pqc_sig_verify(const pqc_ctx_t *p,
    const uint8_t *sig, uint64_t siglen,
    const uint8_t *m, uint64_t mlen,
    const uint8_t *pk) {
    return !((pqc_sig_ctx_t *)p)->verify(sig, siglen, m, mlen, pk);
}

uint32_t pqc_ciphertext_bsz(const pqc_ctx_t *p) {
    return ((pqc_kem_ctx_t *)p)->ciphertext_bsz;
}

uint32_t pqc_shared_secret_bsz(const pqc_ctx_t *p) {
    return ((pqc_kem_ctx_t *)p)->secret_bsz;
}

uint32_t pqc_signature_bsz(const pqc_ctx_t *p) {
    return ((pqc_sig_ctx_t *)p)->sign_bsz;
}

uint32_t pqc_public_key_bsz(const pqc_ctx_t *p) {
    return p->pub_key_bsz;
}

uint32_t pqc_private_key_bsz(const pqc_ctx_t *p) {
    return p->prv_key_bsz;
}

void static_initialization(void) __attribute__((constructor));
void static_initialization(void) {
#ifdef PQC_ASM
    CPU_CAPS = GetX86Info().features;
#endif
}
