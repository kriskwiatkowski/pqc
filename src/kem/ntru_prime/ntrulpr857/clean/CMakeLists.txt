set(
  SRC_CLEAN_NTRULPR857
  crypto_core_multsntrup857.c
  crypto_decode_256x16.c
  crypto_decode_256x2.c
  crypto_decode_857x1723.c
  crypto_decode_857x3.c
  crypto_decode_857xint16.c
  crypto_decode_857xint32.c
  crypto_encode_256x16.c
  crypto_encode_256x2.c
  crypto_encode_857x1723.c
  crypto_encode_857x1723round.c
  crypto_encode_857x3.c
  crypto_encode_857xint16.c
  crypto_sort_int32.c
  crypto_sort_uint32.c
  crypto_stream_aes256ctr.c
  crypto_verify_1312.c
  kem.c
)

define_kem_alg(ntrulpr857_clean
  PQCLEAN_NTRULPR857_CLEAN "${SRC_CLEAN_NTRULPR857}" "${CMAKE_CURRENT_SOURCE_DIR}")
