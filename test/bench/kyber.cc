#include <array>
#include <stdint.h>
#include <utility>

#include <benchmark/benchmark.h>
#include <benchmark/../../src/statistics.h>
#include <benchmark/../../src/cycleclock.h>

#include <pqc/pqc.h>
#include <common/ct_check.h>

#include "kem/kyber/kyber512/avx2/polyvec.h"

extern "C" {
	#include "kem/kyber/kyber512/avx2/indcpa.h"
    #include "kem/kyber/kyber512/avx2/kem.h"
    #include "kem/kyber/kyber512/avx2/rejsample.h"
    #include "kem/kyber/kyber512/avx2/ntt.h"
}

auto cpucycle = [](benchmark::State &st, int64_t cycles) {
    st.counters["CPU cycles: mean"] = benchmark::Counter(
        cycles, benchmark::Counter::kAvgIterations | benchmark::Counter::kResultNoFormat);
};

static void BenchKyberMatK2(benchmark::State &st) {
	int64_t t, total = 0;
	polyvec a[KYBER_K];
	uint8_t seed[32] = {0};
    for (auto _ : st) {
        t = benchmark::cycleclock::Now();
        PQCLEAN_KYBER512_AVX2_gen_matrix(a, seed, 0);
        total += benchmark::cycleclock::Now() - t;
        benchmark::DoNotOptimize(a);
    }
    cpucycle(st, total);
}

static void BenchKyberRejSampling(benchmark::State &st) {
    int64_t t, total = 0;
    int16_t a[256] = {0};
    uint8_t buf[168*3] = {0};
    for (auto _ : st) {
        t = benchmark::cycleclock::Now();
        PQCLEAN_KYBER512_AVX2_rej_uniform_avx(a, buf);
        total += benchmark::cycleclock::Now() - t;
        benchmark::DoNotOptimize(a);
    }
    cpucycle(st, total);
}

static void BenchKyberKeygen(benchmark::State &st) {
    int64_t t, total = 0;
    uint8_t sk[1632];
    uint8_t pk[800];
    for (auto _ : st) {
        t = benchmark::cycleclock::Now();
        PQCLEAN_KYBER512_AVX2_crypto_kem_keypair(pk, sk);
        total += benchmark::cycleclock::Now() - t;
        benchmark::DoNotOptimize(pk);
        benchmark::DoNotOptimize(sk);
    }
    cpucycle(st, total);
}

static void BenchKyberEncaps(benchmark::State &st) {
    int64_t t, total = 0;
    uint8_t sk[1632];
    uint8_t pk[800];
    uint8_t ct[768];
    uint8_t ss[32];
    PQCLEAN_KYBER512_AVX2_crypto_kem_keypair(pk, sk);
    for (auto _ : st) {
        t = benchmark::cycleclock::Now();
        PQCLEAN_KYBER512_AVX2_crypto_kem_enc(ss, ct, pk);
        total += benchmark::cycleclock::Now() - t;
        benchmark::DoNotOptimize(pk);
    }
    cpucycle(st, total);
}

static void BenchKyberDecaps(benchmark::State &st) {
    int64_t t, total = 0;
    uint8_t sk[1632];
    uint8_t pk[800];
    uint8_t ct[768];
    uint8_t ss[32];
    PQCLEAN_KYBER512_AVX2_crypto_kem_keypair(pk, sk);
        PQCLEAN_KYBER512_AVX2_crypto_kem_enc(ss, ct, pk);
    for (auto _ : st) {
        t = benchmark::cycleclock::Now();
        PQCLEAN_KYBER512_AVX2_crypto_kem_dec(ss, ct, sk);
        total += benchmark::cycleclock::Now() - t;
        benchmark::DoNotOptimize(sk);
    }
    cpucycle(st, total);
}

static void BenchKyberBaseMulAVX(benchmark::State &st) {
    int64_t t, total = 0;
    __m256i r[32],a[32],b[32],data[32];

    for (auto _ : st) {
        t = benchmark::cycleclock::Now();
        PQCLEAN_KYBER512_AVX2_basemul_avx(r,a,b,data);
        total += benchmark::cycleclock::Now() - t;
        benchmark::DoNotOptimize(r);
    }
    cpucycle(st, total);
}

static void BenchKyberNttAVX(benchmark::State &st) {
    int64_t t, total = 0;
    __m256i r[32],data[32];
    for (auto _ : st) {
        t = benchmark::cycleclock::Now();
        PQCLEAN_KYBER512_AVX2_ntt_avx(r, data);
        total += benchmark::cycleclock::Now() - t;
        benchmark::DoNotOptimize(r);
    }
    cpucycle(st, total);
}

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


BENCHMARK(BenchKyberMatK2);
BENCHMARK(BenchKyberRejSampling);
BENCHMARK(BenchKyberKeygen);
BENCHMARK(BenchKyberBaseMulAVX);
BENCHMARK(BenchKyberNttAVX);

// TODO: not sure why but memcheck fails in INDCPA encryption
BENCHMARK(BenchKyberEncaps);
BENCHMARK(BenchKyberDecaps);
BENCHMARK(BenchFrodoDecaps);