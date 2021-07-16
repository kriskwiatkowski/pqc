#include <array>
#include <stdint.h>
#include <utility>

#include <benchmark/benchmark.h>
#include <benchmark/../../src/statistics.h>
#include <benchmark/../../src/cycleclock.h>

#include <pqc/pqc.h>
#include <common/ct_check.h>

static void BenchFrodoDecaps(benchmark::State &st) {
    const pqc_ctx_t *p = pqc_kem_alg_by_id(PQC_ALG_KEM_FRODOKEM640SHAKE);
    std::vector<uint8_t> ct(pqc_ciphertext_bsz(p));
    std::vector<uint8_t> ss1(pqc_shared_secret_bsz(p));
    std::vector<uint8_t> ss2(pqc_shared_secret_bsz(p));
    std::vector<uint8_t> sk(pqc_private_key_bsz(p));
    std::vector<uint8_t> pk(pqc_public_key_bsz(p));

    // Generate keys & perform encapsulation
    pqc_keygen(p, pk.data(), sk.data());
    pqc_kem_encapsulate(p, ct.data(), ss1.data(), pk.data());

    // Poison & Decapsulate
    ct_poison(sk.data(), 16);
    ct_poison((unsigned char*)sk.data()+16+9616, 2*640*8 /*CRYPTO_SECRETBYTES*/);
    ct_expect_uum();
    for (auto _ : st) {
        pqc_kem_decapsulate(p, ss2.data(), ct.data(), sk.data());
    }
    ct_require_uum();
    benchmark::DoNotOptimize(ss2);
    benchmark::DoNotOptimize(ct);
    benchmark::DoNotOptimize(sk);
}

BENCHMARK(BenchFrodoDecaps);
