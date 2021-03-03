set(
  SRC_AVX2_FALCON512
  codec.c
  common.c
  fft.c
  fpr.c
  keygen.c
  pqclean.c
  rng.c
  sign.c
  vrfy.c)

define_sig_alg(
  falcon512_avx2
  PQCLEAN_FALCON512_AVX2 "${SRC_AVX2_FALCON512}" "${CMAKE_CURRENT_SOURCE_DIR}")
