#ifndef PQC_COMMON_UTILS_
#define PQC_COMMON_UTILS_

#include <cpuinfo_x86.h>

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


const X86Features * const get_cpu_caps(void);

#endif