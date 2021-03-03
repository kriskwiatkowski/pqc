set(
  SRC_CLEAN_DILITHIUM3
  ntt.c
  packing.c
  poly.c
  polyvec.c
  reduce.c
  rounding.c
  sign.c
  symmetric-shake.c
)

define_sig_alg(dilithium3_clean
  PQCLEAN_DILITHIUM3_CLEAN "${SRC_CLEAN_DILITHIUM3}" "${CMAKE_CURRENT_SOURCE_DIR}")

