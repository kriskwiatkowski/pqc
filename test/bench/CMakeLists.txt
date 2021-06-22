cmake_minimum_required(VERSION 3.13)

include_directories(${PROJECT_SOURCE_DIR}/3rd/gbench/include)
link_directories(${CMAKE_CURRENT_BINARY_DIR}/../../3rd/gbench/lib)

add_executable(
    bench
    kyber.cc
)

target_link_libraries(
    bench

    pqc
    benchmark
    benchmark_main
    cxx
    cxxabi
)

