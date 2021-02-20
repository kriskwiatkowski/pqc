cmake_minimum_required(VERSION 3.13)
project(cryptocore NONE)

enable_language(C)
enable_language(CXX)
enable_language(ASM)

set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "~/.cmake/Modules")
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "3rd/cmake-modules")
set(CMAKE_CXX_STANDARD 11)

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

# Control Debug/Release mode
if(CMAKE_BUILD_TYPE_LOWER STREQUAL "debug")
  set(C_CXX_FLAGS "${C_CXX_FLAGS} -g3 -O0 -Wno-unused")
else()
  set(C_CXX_FLAGS "${C_CXX_FLAGS} -O3")
endif()

include_directories(
  inc
  src
)

# Set CPU architecture
set(CMAKE_C_FLAGS "${C_CXX_FLAGS} -D${ARCH}")
set(CMAKE_CXX_FLAGS "${C_CXX_FLAGS} -D${ARCH}")

# Common function for defining algorithm component
function(define_crypto_alg name namespace src inc test_src)
  add_library(
    pqclean_${name}
    OBJECT
    ${src}
  )

  target_include_directories(
    pqclean_${name} PRIVATE
    common
    ${inc}
  )

  target_compile_definitions(
    pqclean_${name} PRIVATE
    -DPQCLEAN_NAMESPACE=${namespace}
  )

  add_library(
    pqclean_test_${name}
    OBJECT
    ${test_src}
  )

  target_compile_definitions(
    pqclean_test_${name} PRIVATE
    -DPQCLEAN_NAMESPACE=${namespace}
  )

  target_include_directories(
    pqclean_test_${name} PRIVATE
    common
    ${inc}
  )

  add_executable(
    test_runner_${name}
  )
  target_link_libraries(
    test_runner_${name}

    common
    pqclean_${name}
    pqclean_test_${name}
  )
endfunction()

function(define_kem_alg name namespace src inc)
  define_crypto_alg(${name} ${namespace} "${src}" "${inc}" test/crypto_kem/testvectors.c)
endfunction()
function(define_sig_alg name namespace src inc)
  define_crypto_alg(${name} ${namespace} "${src}" "${inc}" test/crypto_sign/testvectors.c)
endfunction()

# Define sources of the components
set(
  SRC_CLEAN_DILITHIUM2
  crypto_sign/dilithium2/clean/ntt.c
  crypto_sign/dilithium2/clean/packing.c
  crypto_sign/dilithium2/clean/poly.c
  crypto_sign/dilithium2/clean/polyvec.c
  crypto_sign/dilithium2/clean/reduce.c
  crypto_sign/dilithium2/clean/rounding.c
  crypto_sign/dilithium2/clean/sign.c
  crypto_sign/dilithium2/clean/symmetric-shake.c
)

set(
  INC_CLEAN_DILITHIUM2
  crypto_sign/dilithium2/clean
)
define_sig_alg(dilithium2_clean
  PQCLEAN_DILITHIUM2_CLEAN "${SRC_CLEAN_DILITHIUM2}" "${INC_CLEAN_DILITHIUM2}")

set(
  SRC_CLEAN_DILITHIUM3
  crypto_sign/dilithium3/clean/ntt.c
  crypto_sign/dilithium3/clean/packing.c
  crypto_sign/dilithium3/clean/poly.c
  crypto_sign/dilithium3/clean/polyvec.c
  crypto_sign/dilithium3/clean/reduce.c
  crypto_sign/dilithium3/clean/rounding.c
  crypto_sign/dilithium3/clean/sign.c
  crypto_sign/dilithium3/clean/symmetric-shake.c
)

set(
  INC_CLEAN_DILITHIUM3
  crypto_sign/dilithium3/clean
)
define_sig_alg(dilithium3_clean
  PQCLEAN_DILITHIUM3_CLEAN "${SRC_CLEAN_DILITHIUM3}" "${INC_CLEAN_DILITHIUM3}")

set(
  SRC_CLEAN_DILITHIUM5
  crypto_sign/dilithium5/clean/ntt.c
  crypto_sign/dilithium5/clean/packing.c
  crypto_sign/dilithium5/clean/poly.c
  crypto_sign/dilithium5/clean/polyvec.c
  crypto_sign/dilithium5/clean/reduce.c
  crypto_sign/dilithium5/clean/rounding.c
  crypto_sign/dilithium5/clean/sign.c
  crypto_sign/dilithium5/clean/symmetric-shake.c
)

set(
  INC_CLEAN_DILITHIUM5
  crypto_sign/dilithium5/clean
)

define_sig_alg(dilithium5_clean
  PQCLEAN_DILITHIUM5_CLEAN "${SRC_CLEAN_DILITHIUM5}" "${INC_CLEAN_DILITHIUM5}")

set(
  SRC_CLEAN_KYBER512
  crypto_kem/kyber512/clean/cbd.c
  crypto_kem/kyber512/clean/indcpa.c
  crypto_kem/kyber512/clean/kem.c
  crypto_kem/kyber512/clean/ntt.c
  crypto_kem/kyber512/clean/poly.c
  crypto_kem/kyber512/clean/polyvec.c
  crypto_kem/kyber512/clean/reduce.c
  crypto_kem/kyber512/clean/symmetric-shake.c
  crypto_kem/kyber512/clean/verify.c
)
set(
  INC_CLEAN_KYBER512
  crypto_kem/kyber512/clean
)
define_kem_alg(kyber512_clean
  PQCLEAN_KYBER512_CLEAN "${SRC_CLEAN_KYBER512}" "${INC_CLEAN_KYBER512}")

# AVX2 targets
if(${ARCH} STREQUAL "ARCH_x86_64")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -march=haswell")

set(
  SRC_AVX2_DILITHIUM2
  crypto_sign/dilithium2/avx2/consts.c
  crypto_sign/dilithium2/avx2/f1600x4.S
  crypto_sign/dilithium2/avx2/fips202x4.c
  crypto_sign/dilithium2/avx2/invntt.S
  crypto_sign/dilithium2/avx2/ntt.S
  crypto_sign/dilithium2/avx2/packing.c
  crypto_sign/dilithium2/avx2/pointwise.S
  crypto_sign/dilithium2/avx2/poly.c
  crypto_sign/dilithium2/avx2/polyvec.c
  crypto_sign/dilithium2/avx2/rejsample.c
  crypto_sign/dilithium2/avx2/rounding.c
  crypto_sign/dilithium2/avx2/shuffle.S
  crypto_sign/dilithium2/avx2/sign.c
  crypto_sign/dilithium2/avx2/symmetric-shake.c)
set(
  INC_AVX2_DILITHIUM2
  crypto_sign/dilithium2/avx2
)
define_sig_alg(dilithium2_avx2
  PQCLEAN_DILITHIUM2_AVX2 "${SRC_AVX2_DILITHIUM2}" "${INC_AVX2_DILITHIUM2}")

set(
  SRC_AVX2_DILITHIUM3
  crypto_sign/dilithium3/avx2/consts.c
  crypto_sign/dilithium3/avx2/f1600x4.S
  crypto_sign/dilithium3/avx2/fips202x4.c
  crypto_sign/dilithium3/avx2/invntt.S
  crypto_sign/dilithium3/avx2/ntt.S
  crypto_sign/dilithium3/avx2/packing.c
  crypto_sign/dilithium3/avx2/pointwise.S
  crypto_sign/dilithium3/avx2/poly.c
  crypto_sign/dilithium3/avx2/polyvec.c
  crypto_sign/dilithium3/avx2/rejsample.c
  crypto_sign/dilithium3/avx2/rounding.c
  crypto_sign/dilithium3/avx2/shuffle.S
  crypto_sign/dilithium3/avx2/sign.c
  crypto_sign/dilithium3/avx2/symmetric-shake.c)
set(
  INC_AVX2_DILITHIUM3
  crypto_sign/dilithium3/avx2
)
define_sig_alg(dilithium3_avx2
  PQCLEAN_DILITHIUM3_AVX2 "${SRC_AVX2_DILITHIUM3}" "${INC_AVX2_DILITHIUM3}")

set(
  SRC_AVX2_DILITHIUM5
  crypto_sign/dilithium5/avx2/consts.c
  crypto_sign/dilithium5/avx2/f1600x4.S
  crypto_sign/dilithium5/avx2/fips202x4.c
  crypto_sign/dilithium5/avx2/invntt.S
  crypto_sign/dilithium5/avx2/ntt.S
  crypto_sign/dilithium5/avx2/packing.c
  crypto_sign/dilithium5/avx2/pointwise.S
  crypto_sign/dilithium5/avx2/poly.c
  crypto_sign/dilithium5/avx2/polyvec.c
  crypto_sign/dilithium5/avx2/rejsample.c
  crypto_sign/dilithium5/avx2/rounding.c
  crypto_sign/dilithium5/avx2/shuffle.S
  crypto_sign/dilithium5/avx2/sign.c
  crypto_sign/dilithium5/avx2/symmetric-shake.c)
set(
  INC_AVX2_DILITHIUM5
  crypto_sign/dilithium5/avx2
)
define_sig_alg(dilithium5_avx2
  PQCLEAN_DILITHIUM5_AVX2 "${SRC_AVX2_DILITHIUM5}" "${INC_AVX2_DILITHIUM5}")

set(
  SRC_AVX2_KYBER512
  crypto_kem/kyber512/avx2/cbd.c
  crypto_kem/kyber512/avx2/consts.c
  crypto_kem/kyber512/avx2/fips202x4.c
  crypto_kem/kyber512/avx2/indcpa.c
  crypto_kem/kyber512/avx2/kem.c
  crypto_kem/kyber512/avx2/poly.c
  crypto_kem/kyber512/avx2/polyvec.c
  crypto_kem/kyber512/avx2/rejsample.c
  crypto_kem/kyber512/avx2/symmetric-shake.c
  crypto_kem/kyber512/avx2/verify.c
  crypto_kem/kyber512/avx2/basemul.S
  crypto_kem/kyber512/avx2/fq.S
  crypto_kem/kyber512/avx2/invntt.S
  crypto_kem/kyber512/avx2/ntt.S
  crypto_kem/kyber512/avx2/shuffle.S
)

set(
  INC_AVX2_KYBER512
  crypto_kem/kyber512/avx2
)

define_kem_alg(kyber512_avx2
  PQCLEAN_KYBER512_AVX2 "${SRC_AVX2_KYBER512}" "${INC_AVX2_KYBER512}")
endif()

# The rest of the library
set(SRC_COMMON_GENERIC
  common/fips202.c
  common/sp800-185.c
  common/randombytes.c
)

if(${ARCH} STREQUAL "ARCH_x86_64")
set(SRC_COMMON_AVX2
  common/keccak4x/KeccakP-1600-times4-SIMD256.c
)
endif()

add_library(
  common
  OBJECT
  ${SRC_COMMON_GENERIC}
  ${SRC_COMMON_AVX2}
)

add_library(
  pqclean
  SHARED
)

add_library(
  pqclean_s
  STATIC
)

target_link_libraries(
  pqclean
  common
  pqclean_dilithium2_clean
  pqclean_dilithium3_clean
  pqclean_dilithium5_clean
)

target_link_libraries(
  pqclean_s
  common
  pqclean_dilithium2_clean
  pqclean_dilithium3_clean
  pqclean_dilithium5_clean
)

# TODO: this requires changes to testvectors.c
# add_executable(
#   test
# )
#
# target_link_libraries(
#   test
#   pqclean_s
#   pqclean_test_dilithium2_clean
#   pqclean_test_dilithium3_clean
#   pqclean_test_dilithium5_clean
# )
