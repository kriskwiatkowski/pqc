cmake_minimum_required(VERSION 3.13)
set(CMAKE_CXX_STANDARD 14)

include_directories(${PROJECT_SOURCE_DIR}/3rd/gbench/include)
link_directories(${CMAKE_CURRENT_BINARY_DIR}/../../3rd/gbench/lib)

if (MEMSAN)
set(CXXLIBS_FOR_MEMORY_SANITIZER cxx cxxabi)
endif()

add_executable(
    bench
    kyber.cc
    main.cc
    sphincs.cc)

target_link_libraries(
    bench

    pqc
    benchmark
    benchmark_main
    ${CXXLIBS_FOR_MEMORY_SANITIZER})

if (MEMSAN)
add_dependencies(bench ${CXXLIBS_FOR_MEMORY_SANITIZER})
endif()
