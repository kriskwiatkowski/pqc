#include <stdint.h>
#include <stddef.h>
#include <common/ct_check.h>

// EXAMPLE how memcheck won't recognize this as a bug, but valgrind will do
#define ENABLE_EXAMPLE_MEMCHECK_VS_VALGRIND 0

#if ENABLE_EXAMPLE_MEMCHECK_VS_VALGRIND
// Constant time memcmp. Returns 0 if p==q, otherwise 1
uint8_t ct_memcmp(const void *a, const void *b, size_t n) {
    const uint8_t *pa = (uint8_t *) a, *pb = (uint8_t *) b;
    uint64_t r = 0;

    ct_poison(&r, 8); // -- this would trigger UUM in the ConstantTime.CtCheck_memcmp_chained testg

    while (n--) { r |= *pa++ ^ *pb++; }
    r = (r >> 1) - r; // MSB == 1 iff r!=0
    return (r>>63)&1; // CHECK: propagation rules make a difference
}
#else
// Constant time memcmp. Returns 0 if p==q, otherwise 1
uint8_t ct_memcmp(const void *a, const void *b, size_t n) {
    const uint8_t *pa = (uint8_t *) a, *pb = (uint8_t *) b;
    uint8_t r = 0;

    while (n--) { r |= *pa++ ^ *pb++; }
    r   = (r >> 1) - r; // MSB == 1 iff r!=0
    r >>= 7;
    return r;
}
#endif
