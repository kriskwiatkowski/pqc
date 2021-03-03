set(
  SRC_AVX2_KYBER768
  basemul.S
  cbd.c
  consts.c
  fips202x4.c
  fq.S
  indcpa.c
  invntt.S
  kem.c
  ntt.S
  poly.c
  polyvec.c
  rejsample.c
  shuffle.S
  symmetric-shake.c
  verify.c
)

define_kem_alg(kyber768_avx2
  PQCLEAN_KYBER768_AVX2 "${SRC_AVX2_KYBER768}" "${CMAKE_CURRENT_SOURCE_DIR}")
