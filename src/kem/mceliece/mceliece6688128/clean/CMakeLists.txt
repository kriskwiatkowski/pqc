set(
  	SRC_CLEAN_MCELIECE6688128
	aes256ctr.c
	benes.c
	bm.c
	controlbits.c
	decrypt.c
	encrypt.c
	gf.c
	operations.c
	pk_gen.c
	root.c
	sk_gen.c
	synd.c
	transpose.c
	util.c
)

define_kem_alg(mceliece6688128_clean
  PQCLEAN_MCELIECE6688128_OPT "${SRC_CLEAN_MCELIECE6688128}" "${CMAKE_CURRENT_SOURCE_DIR}")
