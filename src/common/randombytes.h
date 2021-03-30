#ifndef RANDOMBYTES_H
#define RANDOMBYTES_H
#include <stdint.h>

#ifdef _WIN32
#include <CRTDEFS.H>
#else
#include <unistd.h>
#endif

int randombytes(uint8_t *buf, size_t n)
#if defined(__linux__) && defined(PQC_WEAK_RANDOMBYTES)
// KAT runner defines it's own randombytes, based on DRBG_CTR
__attribute__((weak))
#endif
;

#endif
