set(
  SRC_AVX2_SPHINCS_SHA256_128S_ROBUST
  address.c
  fors.c
  hash_sha256.c
  sha256.c
  sign.c
  thash_sha256_robust.c
  utils.c
  wots.c
  hash_sha256x8.c
  sha256avx.c
  sha256x8.c
  thash_sha256_robustx8.c
  utilsx8.c)

define_sig_alg(
  sphincs_sha256_128s_robust_avx2
  PQCLEAN_SPHINCSSHA256128SROBUST_AVX2 "${SRC_AVX2_SPHINCS_SHA256_128S_ROBUST}" "${CMAKE_CURRENT_SOURCE_DIR}")
