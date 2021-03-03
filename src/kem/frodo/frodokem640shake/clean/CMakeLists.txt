set(
  SRC_CLEAN_FRODOKEM640SHAKE
  kem.c
  matrix_shake.c
  noise.c
  util.c
)

define_kem_alg(frodo640shake_clean
  PQCLEAN_FRODOKEM640SHAKE_OPT "${SRC_CLEAN_FRODOKEM640SHAKE}" "${CMAKE_CURRENT_SOURCE_DIR}")
