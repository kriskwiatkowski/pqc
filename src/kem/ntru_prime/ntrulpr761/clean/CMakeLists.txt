set(
  SRC_CLEAN_NTRULPR761
  crypto_core_multsntrup761.c
  crypto_decode_256x16.c
  crypto_decode_256x2.c
  crypto_decode_761x1531.c
  crypto_decode_761x3.c
  crypto_decode_761xint16.c
  crypto_decode_761xint32.c
  crypto_encode_256x16.c
  crypto_encode_256x2.c
  crypto_encode_761x1531.c
  crypto_encode_761x1531round.c
  crypto_encode_761x3.c
  crypto_encode_761xint16.c
  crypto_sort_int32.c
  crypto_sort_uint32.c
  crypto_stream_aes256ctr.c
  crypto_verify_1167.c
  kem.c
)

define_kem_alg(ntrulpr761_clean
  PQCLEAN_NTRULPR761_CLEAN "${SRC_CLEAN_NTRULPR761}" "${CMAKE_CURRENT_SOURCE_DIR}")
