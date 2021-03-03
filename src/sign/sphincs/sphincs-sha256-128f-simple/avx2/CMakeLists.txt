set(
  SRC_AVX2_SPHINCS_SHA256_128F_SIMPLE
  address.c
  fors.c
  hash_sha256.c
  hash_sha256x8.c
  sha256avx.c
  sha256.c
  sha256x8.c
  sign.c
  thash_sha256_simple.c
  thash_sha256_simplex8.c
  utils.c
  utilsx8.c
  wots.c)

define_sig_alg(
  sphincs_sha256_128f_simple_avx2
  PQCLEAN_SPHINCSSHA256128FSIMPLE_AVX2 "${SRC_AVX2_SPHINCS_SHA256_128F_SIMPLE}" "${CMAKE_CURRENT_SOURCE_DIR}")
