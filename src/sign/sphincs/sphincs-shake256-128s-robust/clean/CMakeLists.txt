set(
  SRC_CLEAN_SPHINCS_SHAKE256_128S_ROBUST
  address.c
  fors.c
  hash_shake256.c
  sign.c
  thash_shake256_robust.c
  utils.c
  wots.c)

define_sig_alg(
  sphincs_shake256_128s_robust_clean
  PQCLEAN_SPHINCSSHAKE256128SROBUST_CLEAN "${SRC_CLEAN_SPHINCS_SHAKE256_128S_ROBUST}" "${CMAKE_CURRENT_SOURCE_DIR}")
