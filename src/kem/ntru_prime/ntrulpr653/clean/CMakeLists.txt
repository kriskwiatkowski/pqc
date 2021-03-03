set(
  SRC_CLEAN_NTRULPR653
  crypto_core_multsntrup653.c
  crypto_decode_256x16.c
  crypto_decode_256x2.c
  crypto_decode_653x1541.c
  crypto_decode_653x3.c
  crypto_decode_653xint16.c
  crypto_decode_653xint32.c
  crypto_encode_256x16.c
  crypto_encode_256x2.c
  crypto_encode_653x1541.c
  crypto_encode_653x1541round.c
  crypto_encode_653x3.c
  crypto_encode_653xint16.c
  crypto_sort_int32.c
  crypto_sort_uint32.c
  crypto_stream_aes256ctr.c
  crypto_verify_1025.c
  kem.c
)

define_kem_alg(ntrulpr653_clean
  PQCLEAN_NTRULPR653_CLEAN "${SRC_CLEAN_NTRULPR653}" "${CMAKE_CURRENT_SOURCE_DIR}")
