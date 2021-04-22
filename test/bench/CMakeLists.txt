cmake_minimum_required(VERSION 3.13)

add_executable(
	bench
	kyber.cc
)

target_link_libraries(
	bench

	pqc
	benchmark
	benchmark_main
)

