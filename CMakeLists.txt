cmake_minimum_required(VERSION 3.13)
project(cryptocore VERSION 0.0.1 LANGUAGES C)

enable_language(C)
enable_language(CXX)
enable_language(ASM)

add_subdirectory(3rd/gtest)
add_subdirectory(3rd/cpu_features)

set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "~/.cmake/Modules")
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "3rd/cmake-modules")
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

string(TOLOWER "${CMAKE_BUILD_TYPE}" CMAKE_BUILD_TYPE_LOWER)

if(${CMAKE_SYSTEM_PROCESSOR} STREQUAL "x86_64")
  set(ARCH "ARCH_x86_64")
elseif(${CMAKE_SYSTEM_PROCESSOR} STREQUAL "amd64")
  set(ARCH "ARCH_x86_64")
elseif(${CMAKE_SYSTEM_PROCESSOR} STREQUAL "AMD64")
  set(ARCH "ARCH_x86_64")
elseif(${CMAKE_SYSTEM_PROCESSOR} STREQUAL "x86")
  set(ARCH "ARCH_x86")
elseif(${CMAKE_SYSTEM_PROCESSOR} STREQUAL "i386")
  set(ARCH "ARCH_x86")
elseif(${CMAKE_SYSTEM_PROCESSOR} STREQUAL "i686")
  set(ARCH "ARCH_x86")
elseif(${CMAKE_SYSTEM_PROCESSOR} STREQUAL "aarch64")
  set(ARCH "ARCH_aarch64")
elseif(${CMAKE_SYSTEM_PROCESSOR} STREQUAL "arm64")
  set(ARCH "ARCH_aarch64")
else()
  message(FATAL_ERROR "Unknown processor:" ${CMAKE_SYSTEM_PROCESSOR})
endif()

if(NOT CMAKE_BUILD_TYPE_LOWER STREQUAL "debug")
  # settings below are required by benchmark library
  set(CMAKE_BUILD_TYPE "Release" CACHE STRING "" FORCE)
  # Target for benchmark - it also builds gtest library
  set(BENCHMARK_ENABLE_GTEST_TESTS ON CACHE BOOL "Enable testing of the benchmark library." FORCE)
  set(BENCHMARK_ENABLE_TESTING OFF CACHE BOOL "Disable benchmark tests" FORCE)
  set(GOOGLETEST_PATH "${CMAKE_SOURCE_DIR}/3rd/gtest" CACHE PATH "Path to the gtest sources" FORCE)
  #if (NOT MACOSX)
  # set(BENCHMARK_ENABLE_LTO ON CACHE BOOL "Enable link time optim" FORCE)
  #endif()
  set(BENCHMARK_ENABLE_INSTALL OFF CACHE BOOL "" FORCE)
  add_subdirectory(${CMAKE_SOURCE_DIR}/3rd/gbench)
endif()

# Arch settings

if (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    set(MACOSX TRUE)
endif()

if(CMAKE_C_COMPILER_ID MATCHES "Clang")
  set(CLANG 1)
endif()

if (MACOSX)
   set(CMAKE_C_COMPILER /usr/bin/cc CACHE PATH "" FORCE)
   set(CMAKE_CXX_COMPILER /usr/bin/c++ CACHE PATH "" FORCE)
endif()

# Global configuration

set(C_CXX_FLAGS
  "-Wno-ignored-qualifiers \
  -Wall \
  -Werror \
  -Wextra \
  -Wpedantic \
  -Wshadow \
  -Wno-variadic-macros \
  -Wundef \
  -Wunused-result")

if(CLANG)
  set(C_CXX_FLAGS
    "-Wconditional-uninitialized \
    -Wmissing-variable-declarations")
endif()

include(.cmake/common.mk)

# Control Debug/Release mode
if(CMAKE_BUILD_TYPE_LOWER STREQUAL "debug")
  set(C_CXX_FLAGS "${C_CXX_FLAGS} -g3 -O0 -Wno-unused")
else()
  set(C_CXX_FLAGS "${C_CXX_FLAGS} -O3")
endif()

include_directories(
  public
  src/common/
  src
  3rd/cpu_features/include
)

set_property(GLOBAL PROPERTY obj_libs "")


# Set CPU architecture
set(CMAKE_C_FLAGS "${C_CXX_FLAGS} -D${ARCH}")
set(CMAKE_CXX_FLAGS "${C_CXX_FLAGS} -D${ARCH}")

if(PQC_WEAK_RANDOMBYTES)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DPQC_WEAK_RANDOMBYTES")
endif()

# Define sources of the components
add_subdirectory(src/sign/dilithium/dilithium2/clean)
add_subdirectory(src/sign/dilithium/dilithium3/clean)
add_subdirectory(src/sign/dilithium/dilithium5/clean)
add_subdirectory(src/sign/falcon/falcon-1024/clean)
add_subdirectory(src/sign/falcon/falcon-512/clean)
add_subdirectory(src/sign/rainbow/rainbowV-classic/clean)
add_subdirectory(src/sign/rainbow/rainbowI-classic/clean)
add_subdirectory(src/sign/rainbow/rainbowIII-classic/clean)
add_subdirectory(src/sign/sphincs/sphincs-sha256-192f-simple/clean)
add_subdirectory(src/sign/sphincs/sphincs-shake256-256f-simple/clean)
add_subdirectory(src/sign/sphincs/sphincs-shake256-192f-robust/clean)
add_subdirectory(src/sign/sphincs/sphincs-shake256-128f-simple/clean)
add_subdirectory(src/sign/sphincs/sphincs-shake256-256s-simple/clean)
add_subdirectory(src/sign/sphincs/sphincs-shake256-128s-simple/clean)
add_subdirectory(src/sign/sphincs/sphincs-sha256-128f-robust/clean)
add_subdirectory(src/sign/sphincs/sphincs-sha256-192s-robust/clean)
add_subdirectory(src/sign/sphincs/sphincs-shake256-128f-robust/clean)
add_subdirectory(src/sign/sphincs/sphincs-shake256-128s-robust/clean)
add_subdirectory(src/sign/sphincs/sphincs-shake256-256s-robust/clean)
add_subdirectory(src/sign/sphincs/sphincs-sha256-192s-simple/clean)
add_subdirectory(src/sign/sphincs/sphincs-shake256-192s-simple/clean)
add_subdirectory(src/sign/sphincs/sphincs-shake256-192s-robust/clean)
add_subdirectory(src/sign/sphincs/sphincs-shake256-192f-simple/clean)
add_subdirectory(src/sign/sphincs/sphincs-sha256-256s-simple/clean)
add_subdirectory(src/sign/sphincs/sphincs-sha256-128s-simple/clean)
add_subdirectory(src/sign/sphincs/sphincs-shake256-256f-robust/clean)
add_subdirectory(src/sign/sphincs/sphincs-sha256-256f-robust/clean)
add_subdirectory(src/sign/sphincs/sphincs-sha256-256f-simple/clean)
add_subdirectory(src/sign/sphincs/sphincs-sha256-256s-robust/clean)
add_subdirectory(src/sign/sphincs/sphincs-sha256-128s-robust/clean)
add_subdirectory(src/sign/sphincs/sphincs-sha256-128f-simple/clean)
add_subdirectory(src/sign/sphincs/sphincs-sha256-192f-robust/clean)

add_subdirectory(src/kem/kyber/kyber512/clean)
add_subdirectory(src/kem/kyber/kyber768/clean)
add_subdirectory(src/kem/kyber/kyber1024/clean)
add_subdirectory(src/kem/saber/lightsaber/clean)
add_subdirectory(src/kem/saber/firesaber/clean)
add_subdirectory(src/kem/saber/saber/clean)
add_subdirectory(src/kem/frodo/frodokem640shake/clean)
add_subdirectory(src/kem/frodo/frodokem976shake/clean)
add_subdirectory(src/kem/frodo/frodokem1344shake/clean)
add_subdirectory(src/kem/ntru/ntruhps4096821/clean)
add_subdirectory(src/kem/ntru/ntruhps2048509/clean)
add_subdirectory(src/kem/ntru/ntruhrss701/clean)
add_subdirectory(src/kem/ntru/ntruhps2048677/clean)
add_subdirectory(src/kem/ntru_prime/ntrulpr761/clean)
add_subdirectory(src/kem/ntru_prime/ntrulpr653/clean)
add_subdirectory(src/kem/ntru_prime/ntrulpr857/clean)
add_subdirectory(src/kem/hqc/hqc-rmrs-128/clean)
add_subdirectory(src/kem/hqc/hqc-rmrs-192/clean)
add_subdirectory(src/kem/hqc/hqc-rmrs-256/clean)
add_subdirectory(src/kem/sike)

# Hardware optimized targets
if(${ARCH} STREQUAL "ARCH_x86_64")

set(CMAKE_C_FLAGS
  "${CMAKE_C_FLAGS} -march=haswell")
set(SRC_COMMON_AVX2
  src/common/keccak4x/KeccakP-1600-times4-SIMD256.c
)

# Sign
add_subdirectory(src/sign/falcon/falcon-512/avx2)
add_subdirectory(src/sign/falcon/falcon-1024/avx2)
add_subdirectory(src/sign/dilithium/dilithium2/avx2)
add_subdirectory(src/sign/dilithium/dilithium3/avx2)
add_subdirectory(src/sign/dilithium/dilithium5/avx2)
add_subdirectory(src/sign/sphincs/sphincs-shake256-128s-simple/avx2)
add_subdirectory(src/sign/sphincs/sphincs-shake256-128f-robust/avx2)
add_subdirectory(src/sign/sphincs/sphincs-shake256-128s-robust/avx2)
add_subdirectory(src/sign/sphincs/sphincs-shake256-128f-simple/avx2)
add_subdirectory(src/sign/sphincs/sphincs-shake256-192s-simple/avx2)
add_subdirectory(src/sign/sphincs/sphincs-shake256-192f-robust/avx2)
add_subdirectory(src/sign/sphincs/sphincs-shake256-192s-robust/avx2)
add_subdirectory(src/sign/sphincs/sphincs-shake256-192f-simple/avx2)
add_subdirectory(src/sign/sphincs/sphincs-shake256-256f-robust/avx2)
add_subdirectory(src/sign/sphincs/sphincs-shake256-256f-simple/avx2)
add_subdirectory(src/sign/sphincs/sphincs-shake256-256s-simple/avx2)
add_subdirectory(src/sign/sphincs/sphincs-shake256-256s-robust/avx2)
add_subdirectory(src/sign/sphincs/sphincs-sha256-128f-robust/avx2)
add_subdirectory(src/sign/sphincs/sphincs-sha256-128s-simple/avx2)
add_subdirectory(src/sign/sphincs/sphincs-sha256-128s-robust/avx2)
add_subdirectory(src/sign/sphincs/sphincs-sha256-128f-simple/avx2)
add_subdirectory(src/sign/sphincs/sphincs-sha256-192s-simple/avx2)
add_subdirectory(src/sign/sphincs/sphincs-sha256-192f-simple/avx2)
add_subdirectory(src/sign/sphincs/sphincs-sha256-192s-robust/avx2)
add_subdirectory(src/sign/sphincs/sphincs-sha256-192f-robust/avx2)
add_subdirectory(src/sign/sphincs/sphincs-sha256-256s-simple/avx2)
add_subdirectory(src/sign/sphincs/sphincs-sha256-256f-robust/avx2)
add_subdirectory(src/sign/sphincs/sphincs-sha256-256f-simple/avx2)
add_subdirectory(src/sign/sphincs/sphincs-sha256-256s-robust/avx2)

# KEMs
add_subdirectory(src/kem/kyber/kyber512/avx2)
add_subdirectory(src/kem/kyber/kyber768/avx2)
add_subdirectory(src/kem/kyber/kyber1024/avx2)
add_subdirectory(src/kem/saber/lightsaber/avx2)
add_subdirectory(src/kem/saber/firesaber/avx2)
add_subdirectory(src/kem/saber/saber/avx2)
add_subdirectory(src/kem/ntru/ntruhps4096821/avx2)
add_subdirectory(src/kem/ntru/ntruhps2048509/avx2)
add_subdirectory(src/kem/ntru/ntruhrss701/avx2)
add_subdirectory(src/kem/ntru/ntruhps2048677/avx2)
add_subdirectory(src/kem/ntru_prime/ntrulpr761/avx2)
add_subdirectory(src/kem/ntru_prime/ntrulpr653/avx2)
add_subdirectory(src/kem/ntru_prime/ntrulpr857/avx2)
add_subdirectory(src/kem/hqc/hqc-rmrs-128/avx2)
add_subdirectory(src/kem/hqc/hqc-rmrs-192/avx2)
add_subdirectory(src/kem/hqc/hqc-rmrs-256/avx2)
endif()



# The rest of the library
set(SRC_COMMON_GENERIC
  src/common/aes.c
  src/common/fips202.c
  src/common/sp800-185.c
  src/common/randombytes.c
  src/common/sha2.c
  src/common/nistseedexpander.c
  src/capi/pqapi.c
)

add_library(
  common
  OBJECT
  ${SRC_COMMON_GENERIC}
  ${SRC_COMMON_AVX2}
)

add_library(
  pqc
  SHARED
)

add_library(
  pqc_s
  STATIC
)
get_property(OBJ_LIBS GLOBAL PROPERTY obj_libs)

target_link_libraries(
  pqc

  ${OBJ_LIBS}
  cpu_features
  common
)

target_link_libraries(
  pqc_s

  cpu_features
  common
  ${OBJ_LIBS}
)

add_executable(
  ut

  test/ut.cpp
)

target_link_libraries(
  ut
  gtest
  gtest_main
  pqc_s)

target_include_directories(
  ut PRIVATE

  ${CMAKE_SOURCE_DIR})

if(NOT CMAKE_BUILD_TYPE_LOWER STREQUAL "debug")
add_subdirectory(test/bench)
endif()

install(TARGETS pqc pqc_s
  PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ GROUP_WRITE WORLD_READ WORLD_WRITE
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib)
install(FILES
  ${QRS_PUBLIC_INC}
  DESTINATION include/pqc)
