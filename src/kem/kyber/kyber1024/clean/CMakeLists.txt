set(
  SRC_CLEAN_KYBER1024
  cbd.c
  indcpa.c
  kem.c
  ntt.c
  poly.c
  polyvec.c
  ../../common/reduce.c
  symmetric-shake.c
  verify.c
)

define_kem_alg(kyber1024_clean
  PQCLEAN_KYBER1024_CLEAN "${SRC_CLEAN_KYBER1024}" "${CMAKE_CURRENT_SOURCE_DIR}")
