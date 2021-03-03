set(
  SRC_AVX2_SABER
  cbd.c
  kem.c
  pack_unpack.c
  poly.c
  poly_mul.c
  SABER_indcpa.c
  verify.c)

define_kem_alg(
  saber_avx2
  PQCLEAN_SABER_AVX2 "${SRC_AVX2_SABER}" "${CMAKE_CURRENT_SOURCE_DIR}")
