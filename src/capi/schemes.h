#ifndef PQC_SCHEMES_
#define PQC_SCHEMES_

// PQClean include
#include "sign/rainbow/rainbowV-classic/clean/api.h"
#include "sign/rainbow/rainbowI-classic/clean/api.h"
#include "sign/rainbow/rainbowIII-classic/clean/api.h"
#include "sign/sphincs/sphincs-sha256-192f-simple/clean/api.h"
#include "sign/sphincs/sphincs-sha256-192f-simple/avx2/api.h"
#include "sign/sphincs/sphincs-shake256-256f-simple/clean/api.h"
#include "sign/sphincs/sphincs-shake256-256f-simple/avx2/api.h"
#include "sign/sphincs/sphincs-shake256-192f-robust/clean/api.h"
#include "sign/sphincs/sphincs-shake256-192f-robust/avx2/api.h"
#include "sign/sphincs/sphincs-shake256-128f-simple/clean/api.h"
#include "sign/sphincs/sphincs-shake256-128f-simple/avx2/api.h"
#include "sign/sphincs/sphincs-shake256-256s-simple/clean/api.h"
#include "sign/sphincs/sphincs-shake256-256s-simple/avx2/api.h"
#include "sign/sphincs/sphincs-shake256-128s-simple/clean/api.h"
#include "sign/sphincs/sphincs-shake256-128s-simple/avx2/api.h"
#include "sign/sphincs/sphincs-sha256-128f-robust/clean/api.h"
#include "sign/sphincs/sphincs-sha256-128f-robust/avx2/api.h"
#include "sign/sphincs/sphincs-sha256-192s-robust/clean/api.h"
#include "sign/sphincs/sphincs-sha256-192s-robust/avx2/api.h"
#include "sign/sphincs/sphincs-shake256-128f-robust/clean/api.h"
#include "sign/sphincs/sphincs-shake256-128f-robust/avx2/api.h"
#include "sign/sphincs/sphincs-shake256-128s-robust/clean/api.h"
#include "sign/sphincs/sphincs-shake256-128s-robust/avx2/api.h"
#include "sign/sphincs/sphincs-shake256-256s-robust/clean/api.h"
#include "sign/sphincs/sphincs-shake256-256s-robust/avx2/api.h"
#include "sign/sphincs/sphincs-sha256-192s-simple/clean/api.h"
#include "sign/sphincs/sphincs-sha256-192s-simple/avx2/api.h"
#include "sign/sphincs/sphincs-shake256-192s-simple/clean/api.h"
#include "sign/sphincs/sphincs-shake256-192s-simple/avx2/api.h"
#include "sign/sphincs/sphincs-shake256-192s-robust/clean/api.h"
#include "sign/sphincs/sphincs-shake256-192s-robust/avx2/api.h"
#include "sign/sphincs/sphincs-shake256-192f-simple/clean/api.h"
#include "sign/sphincs/sphincs-shake256-192f-simple/avx2/api.h"
#include "sign/sphincs/sphincs-sha256-256s-simple/clean/api.h"
#include "sign/sphincs/sphincs-sha256-256s-simple/avx2/api.h"
#include "sign/sphincs/sphincs-sha256-128s-simple/clean/api.h"
#include "sign/sphincs/sphincs-sha256-128s-simple/avx2/api.h"
#include "sign/sphincs/sphincs-shake256-256f-robust/clean/api.h"
#include "sign/sphincs/sphincs-shake256-256f-robust/avx2/api.h"
#include "sign/sphincs/sphincs-sha256-256f-robust/clean/api.h"
#include "sign/sphincs/sphincs-sha256-256f-robust/avx2/api.h"
#include "sign/sphincs/sphincs-sha256-256f-simple/clean/api.h"
#include "sign/sphincs/sphincs-sha256-256f-simple/avx2/api.h"
#include "sign/sphincs/sphincs-sha256-256s-robust/clean/api.h"
#include "sign/sphincs/sphincs-sha256-256s-robust/avx2/api.h"
#include "sign/sphincs/sphincs-sha256-128s-robust/clean/api.h"
#include "sign/sphincs/sphincs-sha256-128s-robust/avx2/api.h"
#include "sign/sphincs/sphincs-sha256-128f-simple/clean/api.h"
#include "sign/sphincs/sphincs-sha256-128f-simple/avx2/api.h"
#include "sign/sphincs/sphincs-sha256-192f-robust/clean/api.h"
#include "sign/sphincs/sphincs-sha256-192f-robust/avx2/api.h"
#include "sign/falcon/falcon-1024/clean/api.h"
#include "sign/falcon/falcon-1024/avx2/api.h"
#include "sign/falcon/falcon-512/clean/api.h"
#include "sign/falcon/falcon-512/avx2/api.h"
#include "sign/dilithium/dilithium2/clean/api.h"
#include "sign/dilithium/dilithium2/avx2/api.h"
#include "sign/dilithium/dilithium3/clean/api.h"
#include "sign/dilithium/dilithium3/avx2/api.h"
#include "sign/dilithium/dilithium5/clean/api.h"
#include "sign/dilithium/dilithium5/avx2/api.h"
#include "kem/ntru/ntruhps4096821/clean/api.h"
#include "kem/ntru/ntruhps4096821/avx2/api.h"
#include "kem/ntru/ntruhps2048509/clean/api.h"
#include "kem/ntru/ntruhps2048509/avx2/api.h"
#include "kem/ntru/ntruhrss701/clean/api.h"
#include "kem/ntru/ntruhrss701/avx2/api.h"
#include "kem/ntru/ntruhps2048677/clean/api.h"
#include "kem/ntru/ntruhps2048677/avx2/api.h"
#include "kem/ntru_prime/ntrulpr761/clean/api.h"
#include "kem/ntru_prime/ntrulpr761/avx2/api.h"
#include "kem/ntru_prime/ntrulpr653/clean/api.h"
#include "kem/ntru_prime/ntrulpr653/avx2/api.h"
#include "kem/ntru_prime/ntrulpr857/clean/api.h"
#include "kem/ntru_prime/ntrulpr857/avx2/api.h"
#include "kem/kyber/kyber768/clean/api.h"
#include "kem/kyber/kyber768/avx2/api.h"
#include "kem/kyber/kyber1024/clean/api.h"
#include "kem/kyber/kyber1024/avx2/api.h"
#include "kem/kyber/kyber512/clean/api.h"
#include "kem/kyber/kyber512/avx2/api.h"
#include "kem/mceliece/mceliece460896f/avx/api.h"
#include "kem/mceliece/mceliece460896f/clean/api.h"
#include "kem/mceliece/mceliece8192128/avx/api.h"
#include "kem/mceliece/mceliece8192128/clean/api.h"
#include "kem/mceliece/mceliece6688128f/avx/api.h"
#include "kem/mceliece/mceliece6688128f/clean/api.h"
#include "kem/mceliece/mceliece8192128f/avx/api.h"
#include "kem/mceliece/mceliece8192128f/clean/api.h"
#include "kem/mceliece/mceliece6960119f/avx/api.h"
#include "kem/mceliece/mceliece6960119f/clean/api.h"
#include "kem/mceliece/mceliece460896/avx/api.h"
#include "kem/mceliece/mceliece460896/clean/api.h"
#include "kem/mceliece/mceliece6688128/avx/api.h"
#include "kem/mceliece/mceliece6688128/clean/api.h"
#include "kem/mceliece/mceliece348864f/avx/api.h"
#include "kem/mceliece/mceliece348864f/clean/api.h"
#include "kem/mceliece/mceliece6960119/avx/api.h"
#include "kem/mceliece/mceliece6960119/clean/api.h"
#include "kem/mceliece/mceliece348864/avx/api.h"
#include "kem/mceliece/mceliece348864/clean/api.h"
#include "kem/frodo/frodokem976shake/clean/api.h"
#include "kem/frodo/frodokem1344shake/clean/api.h"
#include "kem/frodo/frodokem640shake/clean/api.h"
#include "kem/saber/lightsaber/clean/api.h"
#include "kem/saber/lightsaber/avx2/api.h"
#include "kem/saber/firesaber/clean/api.h"
#include "kem/saber/firesaber/avx2/api.h"
#include "kem/saber/saber/clean/api.h"
#include "kem/saber/saber/avx2/api.h"
#include "kem/hqc/hqc-rmrs-128/clean/api.h"
#include "kem/hqc/hqc-rmrs-192/clean/api.h"
#include "kem/hqc/hqc-rmrs-256/clean/api.h"
#include "kem/hqc/hqc-rmrs-128/avx2/api.h"
#include "kem/hqc/hqc-rmrs-192/avx2/api.h"
#include "kem/hqc/hqc-rmrs-256/avx2/api.h"
#include "kem/sike/includes/sike/sike.h"

#endif