#include <stdint.h>
#include <stddef.h>

// Constant time memcmp. Returns 0 if p==q, otherwise 1
uint8_t ct_memcmp(const void *a, const void *b, size_t n) {
    const uint8_t *pa = (uint8_t *) a, *pb = (uint8_t *) b;
    uint8_t r = 0;

    while (n--) { r |= *pa++ ^ *pb++; }
    r   = (r >> 1) - r; // MSB == 1 iff r!=0
    r >>= 7;
    return r;
}
