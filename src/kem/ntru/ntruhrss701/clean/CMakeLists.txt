set(
  SRC_CLEAN_NTRUHRSS701
  cmov.c
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

define_kem_alg(ntruhrss701_clean
  PQCLEAN_NTRUHRSS701_CLEAN "${SRC_CLEAN_NTRUHRSS701}" "${CMAKE_CURRENT_SOURCE_DIR}")
