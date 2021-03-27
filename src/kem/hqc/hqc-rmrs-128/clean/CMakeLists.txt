set(
  	SRC_CLEAN_HQCRMRS128
	code.c
	fft.c
	gf2x.c
	gf.c
	hqc.c
	kem.c
	parsing.c
	reed_muller.c
	reed_solomon.c
	vector.c
)

define_kem_alg(hqcrmrs128_clean
  PQCLEAN_HQCRMRS128_CLEAN "${SRC_CLEAN_HQCRMRS128}" "${CMAKE_CURRENT_SOURCE_DIR}")
