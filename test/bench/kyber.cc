#include <array>
#include <stdint.h>
#include <utility>

#include <benchmark/benchmark.h>
#include <benchmark/../../src/statistics.h>
#include <benchmark/../../src/cycleclock.h>
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
	uint8_t seed[32];
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

BENCHMARK(BenchKyberMatK2);
BENCHMARK(BenchKyberRejSampling);
BENCHMARK(BenchKyberKeygen);
BENCHMARK(BenchKyberEncaps);
BENCHMARK(BenchKyberDecaps);
BENCHMARK(BenchKyberBaseMulAVX);
BENCHMARK(BenchKyberNttAVX);
