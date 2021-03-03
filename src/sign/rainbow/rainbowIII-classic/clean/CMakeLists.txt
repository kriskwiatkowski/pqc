set(
  SRC_CLEAN_RAINBOW_III_CLASSSIC
  blas.c
  blas_comm.c
  gf.c
  parallel_matrix_op.c
  rainbow.c
  rainbow_keypair.c
  rainbow_keypair_computation.c
  sign.c
  utils_hash.c
  utils_prng.c)

define_sig_alg(
  rainbowIIIclassic_clean
  PQCLEAN_RAINBOWIIICLASSIC_CLEAN "${SRC_CLEAN_RAINBOW_III_CLASSSIC}" "${CMAKE_CURRENT_SOURCE_DIR}")
