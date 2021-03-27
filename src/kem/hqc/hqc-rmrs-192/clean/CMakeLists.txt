set(
  	SRC_CLEAN_HQCRMRS192
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

define_kem_alg(hqcrmrs192_clean
  PQCLEAN_HQCRMRS192_CLEAN "${SRC_CLEAN_HQCRMRS192}" "${CMAKE_CURRENT_SOURCE_DIR}")
