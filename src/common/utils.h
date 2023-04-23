#ifndef PQC_COMMON_UTILS_
#define PQC_COMMON_UTILS_

#include <stdint.h>
#include <stddef.h>
#include <cpuinfo_x86.h>

#ifdef __cplusplus
extern "C" {
#endif

// Helper to stringify constants
#define STR(x) STR_(x)
#define STR_(x) #x

/* Concatenate tokens X and Y. Can be done by the "##" operator in
 * simple cases, but has some side effects in more complicated cases.
 */
#define GLUE(a, b) GLUE_(a, b)
#define GLUE_(a, b) a##b

// Rotate 'w'-bit wide value 'v' right by 's' bits.
#define ROTR(v, s, w) (((v) << ((w) - (s))) | ((v) >> (s)))
// Rotate 64-bit value 'v' by 's' bits
#define ROTR64(v,s) ROTR(v,s,64)
// Rotate 32-bit value 'v' by 's' bits
#define ROTR32(v,s) ROTR(v,s,32)

#define ARRAY_LEN(x) sizeof(x)/sizeof(x[0])
#define LOAD32L(x)              \
    (((uint32_t)((x)[0])<< 0) | \
     ((uint32_t)((x)[1])<< 8) | \
     ((uint32_t)((x)[2])<<16) | \
     ((uint32_t)((x)[3])<<24))

#define LOAD64L(x)                       \
    (((uint64_t)LOAD32L((x)+4)) << 32) | \
    (((uint64_t)LOAD32L((x)+0)) <<  0)

#define STORE16B(x,y) do {      \
    (x)[0] = (((y) >> 8)&0xFF); \
    (x)[1] = (((y) >> 0)&0xFF); \
} while(0)
#define LOAD16B(x)            \
    (((uint16_t)(x)[0])<<8 |  \
     ((uint16_t)(x)[1])<<0)
#define LOAD32B(x)                       \
    (((uint32_t)LOAD16B(&(x)[0])<<16) |  \
     ((uint32_t)LOAD16B(&(x)[2])<< 0))
#ifdef __cplusplus
const cpu_features::X86Features*
#else
const X86Features*
#endif
get_cpu_caps(void);

/**
 * \brief Compares two arrays in constant time.
 * \param [in] a first array
 * \param [in] b second arrray
 * \param [in] sz number of bytes to compare
 * \returns 0 if arrays are equal, otherwise 1.
 */
uint8_t ct_memcmp(const void *p, const void *q, size_t n);

#ifdef __cplusplus
}
#endif
#endif
