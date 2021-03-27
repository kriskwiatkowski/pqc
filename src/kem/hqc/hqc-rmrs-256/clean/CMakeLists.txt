set(
  	SRC_CLEAN_HQCRMRS256
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

define_kem_alg(hqcrmrs256_clean
  PQCLEAN_HQCRMRS256_CLEAN "${SRC_CLEAN_HQCRMRS256}" "${CMAKE_CURRENT_SOURCE_DIR}")
