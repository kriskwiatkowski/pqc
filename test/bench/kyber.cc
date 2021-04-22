#include <array>
#include <stdint.h>
#include <utility>

#include <gtest/gtest.h>
#include <benchmark/benchmark.h>
#include <benchmark/../../src/statistics.h>
#include <benchmark/../../src/cycleclock.h>
#include "kem/kyber/kyber512/avx2/polyvec.h"

extern "C" {
	#include "kem/kyber/kyber512/avx2/indcpa.h"
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

BENCHMARK(BenchKyberMatK2);
