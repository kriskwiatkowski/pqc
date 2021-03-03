set(
  SRC_CLEAN_FRODOKEM1344SHAKE
  kem.c
  matrix_shake.c
  noise.c
  util.c
)

define_kem_alg(frodo1344shake_clean
  PQCLEAN_FRODOKEM1344SHAKE_OPT "${SRC_CLEAN_FRODOKEM1344SHAKE}" "${CMAKE_CURRENT_SOURCE_DIR}")
