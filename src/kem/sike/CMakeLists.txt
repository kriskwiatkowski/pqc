set(
  SRC_CLEAN_SIKE_P434
  p434/fpx.c
  p434/fp_generic.c
  p434/fp_glue.c
  p434/fp-x86_64.S
  p434/isogeny.c
  p434/params.c
  p434/sike.c)

define_kem_alg(
  sike_p434_clean
  PQC_SIKEP434_CLEAN "${SRC_CLEAN_SIKE_P434}" "${CMAKE_CURRENT_SOURCE_DIR}")
