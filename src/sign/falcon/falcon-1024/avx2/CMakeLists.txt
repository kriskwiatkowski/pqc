set(
  SRC_AVX2_FALCON1024
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
  falcon1024_avx2
  PQCLEAN_FALCON1024_AVX2 "${SRC_AVX2_FALCON1024}" "${CMAKE_CURRENT_SOURCE_DIR}")
