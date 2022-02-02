#include <benchmark/benchmark.h>

void register_sphincs_benches();

int main(int argc, char** argv)
{
    register_sphincs_benches();
    benchmark::Initialize(&argc, argv);
    benchmark::RunSpecifiedBenchmarks();
}
