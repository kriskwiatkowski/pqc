set(
  SRC_AVX2_SPHINCS_SHAKE256_256S_SIMPLE
  address.c
  fors.c
  hash_shake256.c
  sign.c
  thash_shake256_simple.c
  utils.c
  wots.c
  fips202x4.c
  hash_shake256x4.c
  thash_shake256_simplex4.c
  utilsx4.c)

define_sig_alg(
  sphincs_shake256_256s_simple_avx2
  PQCLEAN_SPHINCSSHAKE256256SSIMPLE_AVX2 "${SRC_AVX2_SPHINCS_SHAKE256_256S_SIMPLE}" "${CMAKE_CURRENT_SOURCE_DIR}")

