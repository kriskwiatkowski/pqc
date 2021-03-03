set(
  SRC_CLEAN_FALCON1024
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
  falcon1024_clean
  PQCLEAN_FALCON1024_CLEAN "${SRC_CLEAN_FALCON1024}" "${CMAKE_CURRENT_SOURCE_DIR}")
