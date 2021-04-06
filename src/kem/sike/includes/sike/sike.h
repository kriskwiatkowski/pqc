#ifndef SIKE_H_
#define SIKE_H_

#include <stdint.h>
#include <string.h>
#include "randombytes.h"

/* SIKE
 *
 * SIKE is a isogeny based post-quantum key encapsulation mechanism. Description of the
 * algorithm is provided in [SIKE]. This implementation uses 434-bit field size. The code
 * is based on "Additional_Implementations" from PQC NIST submission package which can
 * be found here:
 * https://csrc.nist.gov/CSRC/media/Projects/Post-Quantum-Cryptography/documents/round-1/submissions/SIKE.zip
 *
 * [SIKE] https://sike.org/files/SIDH-spec.pdf
 */

// SIKE_PUB_BYTESZ is the number of bytes in a public key.
#define SIKE_PUB_BYTESZ 330
// SIKE_PRV_BYTESZ is the number of bytes in a private key.
#define SIKE_PRV_BYTESZ 28
// SIKE_SS_BYTESZ is the number of bytes in a shared key.
#define SIKE_SS_BYTESZ  16
// SIKE_MSG_BYTESZ is the number of bytes in a random bit string concatenated
// with the public key (see 1.4 of SIKE).
#define SIKE_MSG_BYTESZ 16
// SIKE_SS_BYTESZ is the number of bytes in a ciphertext.
#define SIKE_CT_BYTESZ  (SIKE_PUB_BYTESZ + SIKE_MSG_BYTESZ)

// SIKE_keypair outputs a public and secret key.  In case of success
// function returns 1, otherwise 0.
 int SIKE_keypair(
    uint8_t out_priv[SIKE_PRV_BYTESZ],
    uint8_t out_pub[SIKE_PUB_BYTESZ]);

// SIKE_encaps generates and encrypts a random session key, writing those values to
// |out_shared_key| and |out_ciphertext|, respectively.
 void SIKE_encaps(
    uint8_t out_shared_key[SIKE_SS_BYTESZ],
    uint8_t out_ciphertext[SIKE_CT_BYTESZ],
    const uint8_t pub_key[SIKE_PUB_BYTESZ]);

// SIKE_decaps outputs a random session key, writing it to |out_shared_key|.
 void SIKE_decaps(
    uint8_t out_shared_key[SIKE_SS_BYTESZ],
    const uint8_t ciphertext[SIKE_CT_BYTESZ],
    const uint8_t pub_key[SIKE_PUB_BYTESZ],
    const uint8_t priv_key[SIKE_PRV_BYTESZ]);

// boilerplate needed for integration
#define PQCLEAN_SIKE434_CLEAN_CRYPTO_SECRETKEYBYTES  SIKE_PRV_BYTESZ+SIKE_MSG_BYTESZ
#define PQCLEAN_SIKE434_CLEAN_CRYPTO_PUBLICKEYBYTES  SIKE_PUB_BYTESZ
#define PQCLEAN_SIKE434_CLEAN_CRYPTO_CIPHERTEXTBYTES SIKE_CT_BYTESZ
#define PQCLEAN_SIKE434_CLEAN_CRYPTO_BYTES           SIKE_SS_BYTESZ
#define PQCLEAN_SIKE434_CLEAN_CRYPTO_ALGNAME         "SIKE/p434"

#define PQCLEAN_SIKE434_AVX2_CRYPTO_SECRETKEYBYTES  SIKE_PRV_BYTESZ+SIKE_MSG_BYTESZ
#define PQCLEAN_SIKE434_AVX2_CRYPTO_PUBLICKEYBYTES  SIKE_PUB_BYTESZ
#define PQCLEAN_SIKE434_AVX2_CRYPTO_CIPHERTEXTBYTES SIKE_CT_BYTESZ
#define PQCLEAN_SIKE434_AVX2_CRYPTO_BYTES           SIKE_SS_BYTESZ
#define PQCLEAN_SIKE434_AVX2_CRYPTO_ALGNAME         "SIKE/p434"

static inline int PQCLEAN_SIKE434_CLEAN_crypto_kem_keypair(uint8_t *pk, uint8_t *sk) {
	SIKE_keypair(sk, pk);
	// KATs require the public key to be concatenated after private key
	// OZAPTF: maybe change KAT tester
	memcpy(&sk[SIKE_MSG_BYTESZ+SIKE_PRV_BYTESZ], pk, SIKE_PUB_BYTESZ);
	return 0;
}
static inline int PQCLEAN_SIKE434_CLEAN_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
	SIKE_encaps(ss,ct,pk);
	return 0;
}

static inline int PQCLEAN_SIKE434_CLEAN_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
	SIKE_decaps(ss, ct, &sk[SIKE_PRV_BYTESZ+SIKE_MSG_BYTESZ], sk);
	return 0;
}


#endif
