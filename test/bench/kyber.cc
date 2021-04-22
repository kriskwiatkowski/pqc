#include <array>
#include <stdint.h>
#include <utility>

#include <gtest/gtest.h>
#include <benchmark/benchmark.h>
#include <benchmark/../../src/statistics.h>
#include <benchmark/../../src/cycleclock.h>

auto cpucycle = [](benchmark::State &st, int64_t cycles) {
    st.counters["CPU cycles: mean"] = benchmark::Counter(
        cycles, benchmark::Counter::kAvgIterations | benchmark::Counter::kResultNoFormat);
};

static void BenchKyberMatK2(benchmark::State &st) {
	int64_t t, total = 0;
    for (auto _ : st) {
        t = benchmark::cycleclock::Now();
        total += benchmark::cycleclock::Now() - t;
    }
    cpucycle(st, total);
}

BENCHMARK(BenchKyberMatK2);
