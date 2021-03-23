#include <stdint.h>
#include "kem/kyber/kyber512/clean/api.h"

// helpers
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


// Parameters of the scheme
typedef struct params_t {
    const uint8_t alg_id;
    const char* alg_name;
    const uint32_t prv_key_bsz;
    const uint32_t pub_key_bsz;
} params_t;

typedef struct kem_params_t {
    params_t p;
    const uint32_t ciphertext_bsz;
    const uint32_t secret_bsz;
} kem_params_t;

typedef struct sig_params_t {
    params_t p;
    const uint32_t sign_bsz;
} sig_params_t;

// Macro magic needed to initialize parameters for a scheme
#define REG_KEM(ID)                         \
{                                           \
    .p.alg_id = ID,                         \
    .p.alg_name = STR(ID),                  \
    .p.prv_key_bsz = PQC_PRV_KEY_BSZ(ID),   \
    .p.pub_key_bsz = PQC_PUB_KEY_BSZ(ID),   \
    .ciphertext_bsz = PQC_CT_BSZ(ID),       \
    .secret_bsz = PQC_KEM_BSZ(ID)           \
}

enum {
    KYBER512
};

const kem_params_t kems[] = {
    REG_KEM(KYBER512)
};
