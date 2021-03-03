set(
  SRC_CLEAN_SPHINCS_SHA256_128S_SIMPLE
  address.c
  fors.c
  hash_sha256.c
  sha256.c
  sign.c
  thash_sha256_simple.c
  utils.c
  wots.c)

define_sig_alg(
  sphincs_sha256_128s_simple_clean
  PQCLEAN_SPHINCSSHA256128SSIMPLE_CLEAN "${SRC_CLEAN_SPHINCS_SHA256_128S_SIMPLE}" "${CMAKE_CURRENT_SOURCE_DIR}")
