set(
  SRC_CLEAN_FIRESABER
  cbd.c
  kem.c
  pack_unpack.c
  poly.c
  poly_mul.c
  SABER_indcpa.c
  verify.c)

define_kem_alg(
  firesaber_clean
  PQCLEAN_FIRESABER_CLEAN "${SRC_CLEAN_FIRESABER}" "${CMAKE_CURRENT_SOURCE_DIR}")
