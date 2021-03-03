set(
  SRC_AVX2_SPHINCS_SHA256_256F_ROBUST
  address.c
  fors.c
  hash_sha256.c
  hash_sha256x8.c
  sha256avx.c
  sha256.c
  sha256x8.c
  sign.c
  thash_sha256_robust.c
  thash_sha256_robustx8.c
  utils.c
  utilsx8.c
  wots.c)

define_sig_alg(
  sphincs_sha256_256f_robust_avx2
  PQCLEAN_SPHINCSSHA256256FROBUST_AVX2 "${SRC_AVX2_SPHINCS_SHA256_256F_ROBUST}" "${CMAKE_CURRENT_SOURCE_DIR}")