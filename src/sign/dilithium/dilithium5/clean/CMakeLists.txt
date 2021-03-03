set(
  SRC_CLEAN_DILITHIUM5
  ntt.c
  packing.c
  poly.c
  polyvec.c
  reduce.c
  rounding.c
  sign.c
  symmetric-shake.c
)

define_sig_alg(dilithium5_clean
  PQCLEAN_DILITHIUM5_CLEAN "${SRC_CLEAN_DILITHIUM5}" "${CMAKE_CURRENT_SOURCE_DIR}")
