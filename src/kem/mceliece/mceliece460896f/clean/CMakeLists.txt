set(
  	SRC_CLEAN_MCELIECE460896F
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

define_kem_alg(mceliece460896f_clean
  PQCLEAN_MCELIECE460896F_OPT "${SRC_CLEAN_MCELIECE460896F}" "${CMAKE_CURRENT_SOURCE_DIR}")
