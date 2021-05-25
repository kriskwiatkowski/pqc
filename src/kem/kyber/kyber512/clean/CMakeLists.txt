set(
  SRC_CLEAN_KYBER512
  cbd.c
  indcpa.c
  kem.c
  ntt.c
  poly.c
  polyvec.c
  symmetric-shake.c
  verify.c
)

define_kem_alg(kyber512_clean
  PQCLEAN_KYBER512_CLEAN "${SRC_CLEAN_KYBER512}" "${CMAKE_CURRENT_SOURCE_DIR}")
