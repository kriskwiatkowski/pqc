cmake_minimum_required(VERSION 3.13)
project(cryptocore VERSION 0.0.1 LANGUAGES C)
include(FetchContent)
include(ExternalProject)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_C_STANDARD 99)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

enable_language(C)
enable_language(CXX)
enable_language(ASM)

if(MEMSAN)
  # PQC_MEMSAN enables usage of some internals from clang
  if (NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "Must use clang if compiled with memory sanitizer.")
  endif()
  if(ADDRSAN)
    message(FATAL_ERROR "Can't use MSAN and ASAN")
  endif()
  include(.cmake/libstd-memory_sanitizer.mk)

  # LLVM project location
  set(LLVM_PRJ ${CMAKE_CURRENT_BINARY_DIR}/3rd/llvm-project)
  set(LLVM_PRJ_LIB ${LLVM_PRJ}/usr/local/lib)
  set(LLVM_PRJ_INC ${LLVM_PRJ}/usr/local/include)

  # Add memory sanitizer instrumented libraries
  set(CMAKE_ARGS_MEMCHECK_LIB "-stdlib=libc++")
  set(CMAKE_ARGS_MEMCHECK_INC "-isystem -I${LLVM_PRJ_INC} -I${LLVM_PRJ_INC}/c++/v1")
  set(CMAKE_ARGS_MEMCHECK_FLAGS "-fsanitize=memory -fsanitize-memory-track-origins=2 -fno-omit-frame-pointer -Wno-unused-command-line-argument")
  set(EXTRA_CXX_FLAGS "${CMAKE_ARGS_MEMCHECK_FLAGS} ${CMAKE_ARGS_MEMCHECK_LIB} ${CMAKE_ARGS_MEMCHECK_INC} -DPQC_MEMSAN_BUILD")
endif()

# Dependencies
ExternalProject_Add(
  gtest_project
  SOURCE_DIR     ${PROJECT_SOURCE_DIR}/3rd/gtest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG        a3460d1aeeaa43fdf137a6adefef10ba0b59fe4b
  PREFIX         ${CMAKE_CURRENT_BINARY_DIR}/3rd/gtest
  INSTALL_DIR    ${CMAKE_CURRENT_BINARY_DIR}/3rd/gtest
  CMAKE_ARGS     -DCMAKE_INSTALL_PREFIX=${CMAKE_CURRENT_BINARY_DIR}/3rd/gtest -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER} -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER} -DCMAKE_CXX_FLAGS=${EXTRA_CXX_FLAGS} -DCMAKE_C_FLAGS=${EXTRA_CXX_FLAGS} -Dgtest_disable_pthreads=ON
)
add_dependencies(gtest_project cxx cxxabi)

FetchContent_Declare(
  gbench
  SOURCE_DIR     ${PROJECT_SOURCE_DIR}/3rd/gbench
  GIT_REPOSITORY https://github.com/kriskwiatkowski/benchmark.git
  GIT_TAG        49862ab56b6b7c3afd87b80bd5d787ed78ce3b96
  GIT_SHALLOW    TRUE
)
FetchContent_Populate(gbench)

FetchContent_Declare(
  cpu_features
  SOURCE_DIR     ${PROJECT_SOURCE_DIR}/3rd/cpu_features
  GIT_REPOSITORY https://github.com/google/cpu_features.git
  GIT_TAG        bc2846e78faeb26b8a46c17df369d4e5f1f9e2bb
  GIT_SHALLOW    TRUE
)
FetchContent_Populate(cpu_features)


set(BUILD_PIC ON CACHE BOOL "")
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

# Arch settings

if (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    set(MACOSX TRUE)
endif()

if(CMAKE_C_COMPILER_ID MATCHES "Clang")
  # Additional flags only useful when compiling with clang
  string(APPEND C_CXX_FLAGS " -Wconditional-uninitialized -Wno-missing-variable-declarations -Wno-unused-command-line-argument")
endif()

if (MACOSX)
   set(CMAKE_C_COMPILER /usr/bin/cc CACHE PATH "" FORCE)
   set(CMAKE_CXX_COMPILER /usr/bin/c++ CACHE PATH "" FORCE)
endif()

# Global configuration

set(C_CXX_FLAGS "${C_CXX_FLAGS} -Wno-ignored-qualifiers \
  -Wall \
  -Werror \
  -Wextra \
  -Wpedantic \
  -Wshadow \
  -Wno-variadic-macros \
  -Wunused-result \
  -Wno-unused-command-line-argument \
  -Wno-undef \
  ${EXTRA_CXX_FLAGS}")

if(CMAKE_COMPILER_IS_GNUCC AND CMAKE_C_COMPILER_VERSION VERSION_GREATER 11.0)
set(C_CXX_FLAGS "${C_CXX_FLAGS} \
  -Wno-stringop-overread \
  -Wno-stringop-overflow \
  -Wno-array-parameter")
endif()

# Build with address sanitizer
if(ADDRSAN)
  set(C_CXX_FLAGS "${C_CXX_FLAGS} -fsanitize=undefined,address,leak -fno-omit-frame-pointer")
  set(LDFLAGS "${LDFLAGS} -fsanitize=undefined,address,leak")
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
set(C_CXX_FLAGS "${C_CXX_FLAGS} -D${ARCH}")

# Build for haswell if on x86_64
if(${ARCH} STREQUAL "ARCH_x86_64")
  string(APPEND C_CXX_FLAGS " -march=haswell")
endif()

set(PQC_CMAKE_C_FLAGS "${PQC_CMAKE_C_FLAGS} ${C_CXX_FLAGS}")
set(PQC_CMAKE_CXX_FLAGS "${PQC_CMAKE_CXX_FLAGS} ${C_CXX_FLAGS}")
set(CMAKE_C_FLAGS ${PQC_CMAKE_C_FLAGS})
set(CMAKE_CXX_FLAGS ${PQC_CMAKE_CXX_FLAGS})

if(PQC_WEAK_RANDOMBYTES)
  string(APPEND PQC_CMAKE_C_FLAGS " -DPQC_WEAK_RANDOMBYTES")
endif()

# Define sources of the components
add_subdirectory(src/sign/dilithium/dilithium2/clean)
add_subdirectory(src/sign/dilithium/dilithium3/clean)
add_subdirectory(src/sign/dilithium/dilithium5/clean)
add_subdirectory(src/sign/falcon)
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
add_subdirectory(src/kem/mceliece/mceliece348864/clean)
add_subdirectory(src/kem/mceliece/mceliece460896/clean)
add_subdirectory(src/kem/mceliece/mceliece6688128/clean)
add_subdirectory(src/kem/mceliece/mceliece6960119/clean)
add_subdirectory(src/kem/mceliece/mceliece8192128/clean)
add_subdirectory(src/kem/mceliece/mceliece348864f/clean)
add_subdirectory(src/kem/mceliece/mceliece460896f/clean)
add_subdirectory(src/kem/mceliece/mceliece6688128f/clean)
add_subdirectory(src/kem/mceliece/mceliece6960119f/clean)
add_subdirectory(src/kem/mceliece/mceliece8192128f/clean)
# Hardware optimized targets

if(${ARCH} STREQUAL "ARCH_x86_64")
set(SRC_COMMON_AVX2
  src/common/keccak4x/KeccakP-1600-times4-SIMD256.c
)

# Sign
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

SET(UT_SRC test/ut.cpp)
if(MEMSAN)
SET(UT_SRC ${UT_SRC} test/ct.cpp)
endif()

add_executable(
  ut
  ${UT_SRC}
)

target_link_libraries(
  ut

  cxx
  cxxabi
  gtest
  gtest_main
  pqc_s)

ExternalProject_Get_Property(gtest_project INSTALL_DIR)
target_include_directories(
  ut PRIVATE

  ${CMAKE_SOURCE_DIR}
  ${INSTALL_DIR}/include)

target_link_directories(
  ut
  PRIVATE
  ${INSTALL_DIR}/lib)

# github CI requires that
add_dependencies(ut gtest_project)

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
  set(CMAKE_C_FLAGS "${C_CXX_FLAGS} ${EXTRA_CXX_FLAGS}")
  set(CMAKE_CXX_FLAGS "${C_CXX_FLAGS} ${EXTRA_CXX_FLAGS}")
  add_subdirectory(${CMAKE_SOURCE_DIR}/3rd/gbench)
  add_subdirectory(test/bench)
endif()

install(TARGETS pqc pqc_s
  PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ GROUP_WRITE WORLD_READ WORLD_WRITE
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib)
install(FILES
  ${QRS_PUBLIC_INC}
  DESTINATION include/pqc)
