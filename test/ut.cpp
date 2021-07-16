#include <algorithm>
#include <random>
#include <vector>

#include <gtest/gtest.h>
#include <pqc/pqc.h>
#include <common/ct_check.h>

TEST(KEM,OneOff) {

    for (int i=0; i<PQC_ALG_KEM_MAX; i++) {
        const pqc_ctx_t *p = pqc_kem_alg_by_id(i);

        std::vector<uint8_t> ct(pqc_ciphertext_bsz(p));
        std::vector<uint8_t> ss1(pqc_shared_secret_bsz(p));
        std::vector<uint8_t> ss2(pqc_shared_secret_bsz(p));
        std::vector<uint8_t> sk(pqc_private_key_bsz(p));
        std::vector<uint8_t> pk(pqc_public_key_bsz(p));

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

TEST(SIGN,OneOff) {

    std::random_device rd;
    std::uniform_int_distribution<uint8_t> dist(0, 0xFF);
    uint8_t msg[1234] = {0};

    for (int i=0; i<PQC_ALG_SIG_MAX; i++) {
        const pqc_ctx_t *p = pqc_sig_alg_by_id(i);
        // generate some random msg
        for (auto &x : msg) {x = dist(rd);}

        std::vector<uint8_t> sig(pqc_signature_bsz(p));
        std::vector<uint8_t> sk(pqc_private_key_bsz(p));
        std::vector<uint8_t> pk(pqc_public_key_bsz(p));

        ASSERT_TRUE(
            pqc_keygen(p, pk.data(), sk.data()));
        uint64_t sigsz = sig.size();
        ASSERT_TRUE(
            pqc_sig_create(p, sig.data(), &sigsz, msg, 1234, sk.data()));
        ASSERT_TRUE(
            pqc_sig_verify(p, sig.data(), sigsz, msg, 1234, pk.data()));
    }
}

TEST(Frodo, Decaps) {
    const pqc_ctx_t *p = pqc_kem_alg_by_id(PQC_ALG_KEM_FRODOKEM640SHAKE);

    std::vector<uint8_t> ct(pqc_ciphertext_bsz(p));
    std::vector<uint8_t> ss1(pqc_shared_secret_bsz(p));
    std::vector<uint8_t> ss2(pqc_shared_secret_bsz(p));
    std::vector<uint8_t> sk(pqc_private_key_bsz(p));
    std::vector<uint8_t> pk(pqc_public_key_bsz(p));
    bool res;

    ASSERT_TRUE(
        pqc_keygen(p, pk.data(), sk.data()));

    ct_poison(sk.data(), 16);
    ct_poison((unsigned char*)sk.data()+16+9616, 2*640*8 /*CRYPTO_SECRETBYTES*/);
    ASSERT_TRUE(
        pqc_kem_encapsulate(p, ct.data(), ss1.data(), pk.data()));

    // Decapsulate
    ct_expect_uum();
    res = pqc_kem_decapsulate(p, ss2.data(), ct.data(), sk.data());
    ct_require_uum();

    // Purify res to allow non-ct check by ASSERT_TRUE
    ct_purify(&res, 1);
    ASSERT_TRUE(res);

    // ss2 needs to be purified as it originates from poisoned data
    ct_purify(ss2.data(), ss2.size());
    ASSERT_EQ(ss2, ss1);
}

TEST(Frodo, Decaps_Negative) {
    const pqc_ctx_t *p = pqc_kem_alg_by_id(PQC_ALG_KEM_FRODOKEM640SHAKE);

    std::vector<uint8_t> ct(pqc_ciphertext_bsz(p));
    std::vector<uint8_t> ss1(pqc_shared_secret_bsz(p));
    std::vector<uint8_t> ss2(pqc_shared_secret_bsz(p));
    std::vector<uint8_t> sk(pqc_private_key_bsz(p));
    std::vector<uint8_t> pk(pqc_public_key_bsz(p));
    bool res;

    // Setup
    ASSERT_TRUE(
        pqc_keygen(p, pk.data(), sk.data()));
    ct_poison(sk.data(), 16);
    ct_poison(((unsigned char*)sk.data())+16+9616, 2*640*8);

    ASSERT_TRUE(
        pqc_kem_encapsulate(p, ct.data(), ss1.data(), pk.data()));

    // Alter C1 of the ciphertext
    ct[ct.size()-2] ^= 1;

    ct_expect_uum();
    res = pqc_kem_decapsulate(p, ss2.data(), ct.data(), sk.data());
    ct_require_uum();

    // Purify res to allow non-ct check by ASSERT_TRUE
    ct_purify(&res, 1);
    ASSERT_TRUE(res);

    // ss2 needs to be purified as it originates from poisoned data
    ct_purify(ss2.data(), ss2.size());
    ASSERT_NE(ss2, ss1);
}
