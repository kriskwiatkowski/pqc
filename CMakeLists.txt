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
  set(ARCH "QRS_ARCH_x86_64")
elseif(${CMAKE_SYSTEM_PROCESSOR} STREQUAL "amd64")
  set(ARCH "QRS_ARCH_x86_64")
elseif(${CMAKE_SYSTEM_PROCESSOR} STREQUAL "AMD64")
  set(ARCH "QRS_ARCH_x86_64")
elseif(${CMAKE_SYSTEM_PROCESSOR} STREQUAL "x86")
  set(ARCH "QRS_ARCH_x86")
elseif(${CMAKE_SYSTEM_PROCESSOR} STREQUAL "i386")
  set(ARCH "QRS_ARCH_x86")
elseif(${CMAKE_SYSTEM_PROCESSOR} STREQUAL "i686")
  set(ARCH "QRS_ARCH_x86")
elseif(${CMAKE_SYSTEM_PROCESSOR} STREQUAL "aarch64")
  set(ARCH "QRS_ARCH_aarch64")
elseif(${CMAKE_SYSTEM_PROCESSOR} STREQUAL "arm64")
  set(ARCH "QRS_ARCH_aarch64")
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

add_library(
  common
  OBJECT

  common/fips202.c
  common/sp800-185.c
  common/randombytes.c
)

function(define_crypto_alg name namespace src inc)
  add_library(
    pqclean_${name}
    OBJECT
    ${src}
  )

  target_include_directories(
    pqclean_${name} PRIVATE
    common
  )

  target_compile_definitions(
    pqclean_${name} PRIVATE
    -DPQCLEAN_NAMESPACE=${namespace}
  )

  add_library(
    pqclean_test_${name}
    OBJECT
    test/crypto_sign/testvectors.c
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
endfunction()

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

define_crypto_alg(dilithium2_clean
  PQCLEAN_DILITHIUM2_CLEAN "${SRC_CLEAN_DILITHIUM2}" "${INC_CLEAN_DILITHIUM2}")

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
)

target_link_libraries(
  pqclean_s
  common
  pqclean_dilithium2_clean
)

add_executable(
  test
)

target_link_libraries(
  test
  pqclean_s
  pqclean_test_dilithium2_clean
)
