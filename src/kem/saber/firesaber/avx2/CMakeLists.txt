set(
  SRC_AVX2_FIRESABER
  cbd.c
  kem.c
  pack_unpack.c
  poly.c
  poly_mul.c
  SABER_indcpa.c
  verify.c)

define_kem_alg(
  firesaber_avx2
  PQCLEAN_FIRESABER_AVX2 "${SRC_AVX2_FIRESABER}" "${CMAKE_CURRENT_SOURCE_DIR}")
