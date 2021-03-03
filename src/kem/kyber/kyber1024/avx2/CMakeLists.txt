set(
  SRC_AVX2_KYBER1024
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

define_kem_alg(kyber1024_avx2
  PQCLEAN_KYBER1024_AVX2 "${SRC_AVX2_KYBER1024}" "${CMAKE_CURRENT_SOURCE_DIR}")
