#ifndef PQC_COMMON_UTILS_
#define PQC_COMMON_UTILS_

#include <cpuinfo_x86.h>

const X86Features * const get_cpu_caps(void);

#endif