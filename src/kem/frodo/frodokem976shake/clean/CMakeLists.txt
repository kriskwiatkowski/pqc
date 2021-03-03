set(
  SRC_CLEAN_FRODOKEM976SHAKE
  kem.c
  matrix_shake.c
  noise.c
  util.c
)

define_kem_alg(frodo976shake_clean
  PQCLEAN_FRODOKEM976SHAKE_OPT "${SRC_CLEAN_FRODOKEM976SHAKE}" "${CMAKE_CURRENT_SOURCE_DIR}")
