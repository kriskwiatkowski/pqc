if(NOT ${NO_ASM})
add_definitions(-DPQC_ASM=1)
endif()

set(
  SRC_CLEAN_FALCON
  api.c
  codec.c
  common.c
  falcon.c
  fft.c
  fpr.c
  keygen.c
  rng.c
  sign.c
  vrfy.c
)

define_sig_alg(
  falcon1024_clean
  PQCLEAN_FALCON_CLEAN "${SRC_CLEAN_FALCON}" "${CMAKE_CURRENT_SOURCE_DIR}")
