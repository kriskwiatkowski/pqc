#include <algorithm>
#include <vector>
#include <gtest/gtest.h>
#include <pqc/pqc.h>

TEST(Kyber,KEMOneOff) {

	for (int i=0; i<PQC_ALG_KEM_MAX; i++) {
		const params_t *p = pqc_kem_alg_by_id(i);

	    std::vector<uint8_t> ct(ciphertext_bsz(p));
	    std::vector<uint8_t> ss1(shared_secret_bsz(p));
	    std::vector<uint8_t> ss2(shared_secret_bsz(p));
	    std::vector<uint8_t> sk(private_key_bsz(p));
	    std::vector<uint8_t> pk(public_key_bsz(p));

		ASSERT_TRUE(
			pqc_keygen(p, pk.data(), sk.data()));
		ASSERT_TRUE(
			pqc_kem_encapsulate(p, ct.data(), ss1.data(), pk.data()));
		ASSERT_TRUE(
			pqc_kem_decapsulate(p, ss2.data(), ct.data(), sk.data()));
		ASSERT_TRUE(
			std::equal(ss1.begin(), ss1.end(), ss2.begin()));
	}
}

TEST(Kyber,SIGNOneOff) {

	for (int i=0; i<PQC_ALG_SIG_MAX; i++) {
		const params_t *p = pqc_sig_alg_by_id(i);

		uint8_t msg[1234];
	    std::vector<uint8_t> sig(signature_bsz(p));
	    std::vector<uint8_t> sk(private_key_bsz(p));
	    std::vector<uint8_t> pk(public_key_bsz(p));

		ASSERT_TRUE(
			pqc_keygen(p, pk.data(), sk.data()));
		uint64_t sigsz = sig.size();
		ASSERT_TRUE(
			pqc_sig_create(p, sig.data(), &sigsz, msg, 1234, sk.data()));
		ASSERT_TRUE(
			pqc_sig_verify(p, sig.data(), sigsz, msg, 1234, pk.data()));
	}
}
