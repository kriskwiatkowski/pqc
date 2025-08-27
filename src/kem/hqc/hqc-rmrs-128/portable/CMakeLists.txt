set(
  	SRC_PORTABLE_HQCRMRS128
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

define_kem_alg(hqcrmrs128_portable
  PQC_HQC128_PORTABLE "${SRC_PORTABLE_HQCRMRS128}" "${CMAKE_CURRENT_SOURCE_DIR}")
