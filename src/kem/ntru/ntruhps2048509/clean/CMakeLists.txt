set(
  SRC_CLEAN_NTRUHPS2048509
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

define_kem_alg(ntruhps2048509_clean
  PQCLEAN_NTRUHPS2048509_CLEAN "${SRC_CLEAN_NTRUHPS2048509}" "${CMAKE_CURRENT_SOURCE_DIR}")
