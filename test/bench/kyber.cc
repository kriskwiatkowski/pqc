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
BENCHMARK(BenchKyberMatK2);
BENCHMARK(BenchKyberKeygen);
BENCHMARK(BenchKyberEncaps);
BENCHMARK(BenchKyberDecaps);
