set(
  SRC_CLEAN_SPHINCS_SHA256_128F_ROBUST
  address.c
  fors.c
  hash_sha256.c
  sha256.c
  sign.c
  thash_sha256_robust.c
  utils.c
  wots.c)

define_sig_alg(
  sphincs_sha256_128f_robust_clean
  PQCLEAN_SPHINCSSHA256128FROBUST_CLEAN "${SRC_CLEAN_SPHINCS_SHA256_128F_ROBUST}" "${CMAKE_CURRENT_SOURCE_DIR}")
