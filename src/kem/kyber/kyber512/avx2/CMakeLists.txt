set(
  SRC_AVX2_KYBER512
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

define_kem_alg(kyber512_avx2
  PQCLEAN_KYBER512_AVX2 "${SRC_AVX2_KYBER512}" "${CMAKE_CURRENT_SOURCE_DIR}")
