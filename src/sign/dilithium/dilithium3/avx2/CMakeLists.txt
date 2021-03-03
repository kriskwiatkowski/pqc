set(
  SRC_AVX2_DILITHIUM3
  consts.c
  f1600x4.S
  fips202x4.c
  invntt.S
  ntt.S
  packing.c
  pointwise.S
  poly.c
  polyvec.c
  rejsample.c
  rounding.c
  shuffle.S
  sign.c
  symmetric-shake.c)

define_sig_alg(dilithium3_avx2
  PQCLEAN_DILITHIUM3_AVX2 "${SRC_AVX2_DILITHIUM3}" "${CMAKE_CURRENT_SOURCE_DIR}")
