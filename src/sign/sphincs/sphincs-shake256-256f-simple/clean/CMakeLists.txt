set(
  SRC_CLEAN_SPHINCS_SHAKE256_256F_SIMPLE
  address.c
  fors.c
  hash_shake256.c
  sign.c
  thash_shake256_simple.c
  utils.c
  wots.c)

define_sig_alg(
  sphincs_shake256_256f_simple_clean
  PQCLEAN_SPHINCSSHAKE256256FSIMPLE_CLEAN "${SRC_CLEAN_SPHINCS_SHAKE256_256F_SIMPLE}" "${CMAKE_CURRENT_SOURCE_DIR}")
