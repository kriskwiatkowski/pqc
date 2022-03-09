#include <algorithm>
#include <array>
#include <random>
#include <utility>
#include <sstream>
#include <pqc/pqc.h>
#include <benchmark/benchmark.h>
#include <benchmark/../../src/statistics.h>
#include <benchmark/../../src/cycleclock.h>

#define ARRAY_LEN(X) sizeof(X)/sizeof(X[0])


static auto cpucycle = [](benchmark::State &st, int64_t cycles) {
    st.counters["CPU cycles: mean"] = benchmark::Counter(
        cycles, benchmark::Counter::kAvgIterations | benchmark::Counter::kResultNoFormat);
};

struct scheme_t {
    uint8_t id;
    const char* name;
};

#define SCH(SCHEME) {SCHEME, #SCHEME},

#define SIG_LIST(_)	\
	_(PQC_ALG_SIG_SPHINCSSHAKE256128FSIMPLE) \
	_(PQC_ALG_SIG_SPHINCSSHAKE256128SSIMPLE) \
	_(PQC_ALG_SIG_SPHINCSSHAKE256128FROBUST) \
	_(PQC_ALG_SIG_SPHINCSSHAKE256128SROBUST) \
	_(PQC_ALG_SIG_SPHINCSSHAKE256192FSIMPLE) \
	_(PQC_ALG_SIG_SPHINCSSHAKE256192SSIMPLE) \
	_(PQC_ALG_SIG_SPHINCSSHAKE256192FROBUST) \
	_(PQC_ALG_SIG_SPHINCSSHAKE256192SROBUST) \
	_(PQC_ALG_SIG_SPHINCSSHAKE256256FSIMPLE) \
	_(PQC_ALG_SIG_SPHINCSSHAKE256256SSIMPLE) \
	_(PQC_ALG_SIG_SPHINCSSHAKE256256FROBUST) \
	_(PQC_ALG_SIG_SPHINCSSHAKE256256SROBUST) \
	_(PQC_ALG_SIG_SPHINCSSHA256128FSIMPLE) \
	_(PQC_ALG_SIG_SPHINCSSHA256128SSIMPLE) \
	_(PQC_ALG_SIG_SPHINCSSHA256128FROBUST) \
	_(PQC_ALG_SIG_SPHINCSSHA256128SROBUST) \
	_(PQC_ALG_SIG_SPHINCSSHA256192FSIMPLE) \
	_(PQC_ALG_SIG_SPHINCSSHA256192SSIMPLE) \
	_(PQC_ALG_SIG_SPHINCSSHA256192FROBUST) \
	_(PQC_ALG_SIG_SPHINCSSHA256192SROBUST) \
	_(PQC_ALG_SIG_SPHINCSSHA256256FSIMPLE) \
	_(PQC_ALG_SIG_SPHINCSSHA256256SSIMPLE) \
	_(PQC_ALG_SIG_SPHINCSSHA256256FROBUST) \
	_(PQC_ALG_SIG_SPHINCSSHA256256SROBUST)


static const struct scheme_t sig_schemes[] = {
	SIG_LIST(SCH)
};

static void BenchKeyPair(benchmark::State &st) {
    int64_t  t, total = 0;
    uint32_t id = st.range(0);

    const pqc_ctx_t *ctx;
    ctx = pqc_sig_alg_by_id(id);
    std::vector<uint8_t> pk(pqc_public_key_bsz(ctx));
    std::vector<uint8_t> sk(pqc_private_key_bsz(ctx));
    for (auto _ : st) {
        t = benchmark::cycleclock::Now();
        pqc_keygen(ctx, pk.data(), sk.data());
        total += benchmark::cycleclock::Now() - t;
        benchmark::DoNotOptimize(pk);
        benchmark::DoNotOptimize(sk);
    }
    cpucycle(st, total);
}

static void BenchSign(benchmark::State &st) {
    int64_t  t, total = 0;
    struct pqcl_asym_t *key_pair = nullptr;
    uint32_t id = st.range(0);
    uint8_t msg[2048] = {0};
    const pqc_ctx_t *ctx;

    ctx = pqc_sig_alg_by_id(id);
    std::vector<uint8_t> sign(pqc_signature_bsz(ctx));
    std::vector<uint8_t> pk(pqc_public_key_bsz(ctx));
    std::vector<uint8_t> sk(pqc_private_key_bsz(ctx));
    pqc_keygen(ctx, pk.data(), sk.data());
    size_t se_len = sign.size();

    for (auto _ : st) {
        t = benchmark::cycleclock::Now();
        pqc_sig_create(ctx, sign.data(), &se_len, msg, sizeof msg, sk.data());
        total += benchmark::cycleclock::Now() - t;
    }
    cpucycle(st, total);
}

static void BenchVerify(benchmark::State &st) {
    int64_t  t, total = 0;
    struct pqcl_asym_t *key_pair = nullptr;
    uint32_t id = st.range(0);
    const pqc_ctx_t *ctx;
    uint8_t msg[2048] = {0};

    ctx = pqc_sig_alg_by_id(id);
    std::vector<uint8_t> sign(pqc_signature_bsz(ctx));
    std::vector<uint8_t> pk(pqc_public_key_bsz(ctx));
    std::vector<uint8_t> sk(pqc_private_key_bsz(ctx));
    pqc_keygen(ctx, pk.data(), sk.data());

    size_t se_len = sign.size();
    pqc_sig_create(ctx, sign.data(), &se_len, msg, sizeof msg, sk.data());

    for (auto _ : st) {
        t = benchmark::cycleclock::Now();
        pqc_sig_verify(ctx, sign.data(), se_len, msg, sizeof msg, pk.data());
        total += benchmark::cycleclock::Now() - t;
    }
    cpucycle(st, total);
}

void register_sphincs_benches() {
    for (size_t i=0; i<ARRAY_LEN(sig_schemes); i++) {
        std::stringstream s;
        s << "BenchKeyPair<" << sig_schemes[i].name << ">";
        RegisterBenchmark(s.str().c_str(), BenchKeyPair)
            ->Unit(benchmark::kMicrosecond)
            ->Arg(sig_schemes[i].id)->ArgName("");
        s.str(""); s.clear();
        s << "BenchSign<" << sig_schemes[i].name << ">";
        RegisterBenchmark(s.str().c_str(), BenchSign)
            ->Unit(benchmark::kMicrosecond)
            ->Arg(sig_schemes[i].id)->ArgName("");
        s.str(""); s.clear();
        s << "BenchVerify<" << sig_schemes[i].name << ">";
        RegisterBenchmark(s.str().c_str(), BenchVerify)
            ->Unit(benchmark::kMicrosecond)
            ->Arg(sig_schemes[i].id)->ArgName("");
    }
}
