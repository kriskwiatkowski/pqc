set(
  SRC_CLEAN_FALCON512
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
  falcon512_clean
  PQCLEAN_FALCON512_CLEAN "${SRC_CLEAN_FALCON512}" "${CMAKE_CURRENT_SOURCE_DIR}")
