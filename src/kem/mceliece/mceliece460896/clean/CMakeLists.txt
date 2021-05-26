set(
  	SRC_CLEAN_MCELIECE460896
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

define_kem_alg(mceliece460896_clean
  PQCLEAN_MCELIECE460896_OPT "${SRC_CLEAN_MCELIECE460896}" "${CMAKE_CURRENT_SOURCE_DIR}")
