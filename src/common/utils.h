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
     ((uint16_t)(x)[1])<<0)   \

//#if !defined(NDEBUG)
#include <stdio.h>
static inline void dump_buffer_hex(FILE *f, int ind, const void* data, size_t size) {
    if (!f) {
        f = stdout;
    }
    fprintf(f, "%*s", ind, " ");
    for (size_t i = 0; i < size; ++i) {
        fprintf(f, "%02X:", ((uint8_t*)data)[i]);
        if ((i+1) % 32 == 0 || i+1 == size) {
            fprintf(f, "\n%*s", ind, " ");
        }
    }
    fprintf(f,"\n");
}
//#endif

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
