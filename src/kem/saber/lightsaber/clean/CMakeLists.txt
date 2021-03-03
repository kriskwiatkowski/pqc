
set(
  SRC_CLEAN_LIGHTSABER
  cbd.c
  kem.c
  pack_unpack.c
  poly.c
  poly_mul.c
  SABER_indcpa.c
  verify.c)

define_kem_alg(
  lightsaber_clean
  PQCLEAN_LIGHTSABER_CLEAN "${SRC_CLEAN_LIGHTSABER}" "${CMAKE_CURRENT_SOURCE_DIR}")
