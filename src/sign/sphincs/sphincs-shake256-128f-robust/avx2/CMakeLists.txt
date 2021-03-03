set(
  SRC_AVX2_SPHINCS_SHAKE256_128F_ROBUST
  address.c
  fors.c
  hash_shake256.c
  sign.c
  thash_shake256_robust.c
  utils.c
  wots.c
  fips202x4.c
  hash_shake256x4.c
  thash_shake256_robustx4.c
  utilsx4.c)
define_sig_alg(
  sphincs_shake256_128f_robust_avx2
  PQCLEAN_SPHINCSSHAKE256128FROBUST_AVX2 "${SRC_AVX2_SPHINCS_SHAKE256_128F_ROBUST}" "${CMAKE_CURRENT_SOURCE_DIR}")
