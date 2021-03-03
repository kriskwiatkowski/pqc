set(
  SRC_AVX2_LIGHTSABER
  cbd.c
  kem.c
  pack_unpack.c
  poly.c
  poly_mul.c
  SABER_indcpa.c
  verify.c)

define_kem_alg(
  lightsaber_avx2
  PQCLEAN_LIGHTSABER_AVX2 "${SRC_AVX2_LIGHTSABER}" "${CMAKE_CURRENT_SOURCE_DIR}")
