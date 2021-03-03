set(
  SRC_CLEAN_NTRUHPS4096821
  cmov.c
  crypto_sort_int32.c
  kem.c
  owcpa.c
  pack3.c
  packq.c
  poly.c
  poly_lift.c
  poly_mod.c
  poly_r2_inv.c
  poly_rq_mul.c
  poly_s3_inv.c
  sample.c
  sample_iid.c
)

define_kem_alg(ntruhps4096821_clean
  PQCLEAN_NTRUHPS4096821_CLEAN "${SRC_CLEAN_NTRUHPS4096821}" "${CMAKE_CURRENT_SOURCE_DIR}")
