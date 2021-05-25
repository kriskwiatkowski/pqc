set(
  SRC_CLEAN_KYBER768
  cbd.c
  indcpa.c
  kem.c
  ntt.c
  poly.c
  polyvec.c
  symmetric-shake.c
  verify.c
)
set(
  INC_CLEAN_KYBER768
  ${CMAKE_CURRENT_SOURCE_DIR}
)
define_kem_alg(kyber768_clean
  PQCLEAN_KYBER768_CLEAN "${SRC_CLEAN_KYBER768}" "${INC_CLEAN_KYBER768}")
