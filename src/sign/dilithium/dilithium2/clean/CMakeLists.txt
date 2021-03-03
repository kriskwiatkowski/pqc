set(
  SRC_CLEAN_DILITHIUM2
  ntt.c
  packing.c
  poly.c
  polyvec.c
  reduce.c
  rounding.c
  sign.c
  symmetric-shake.c
)

define_sig_alg(dilithium2_clean
  PQCLEAN_DILITHIUM2_CLEAN "${SRC_CLEAN_DILITHIUM2}" "${CMAKE_CURRENT_SOURCE_DIR}")
