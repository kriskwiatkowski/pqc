set(
  SRC_AVX2_DILITHIUM5
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

define_sig_alg(dilithium5_avx2
  PQCLEAN_DILITHIUM5_AVX2 "${SRC_AVX2_DILITHIUM5}" "${CMAKE_CURRENT_SOURCE_DIR}")

