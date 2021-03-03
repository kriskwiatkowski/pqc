set(
  SRC_CLEAN_SABER
  cbd.c
  kem.c
  pack_unpack.c
  poly.c
  poly_mul.c
  SABER_indcpa.c
  verify.c)

define_kem_alg(
  saber_clean
  PQCLEAN_SABER_CLEAN "${SRC_CLEAN_SABER}" "${CMAKE_CURRENT_SOURCE_DIR}")
