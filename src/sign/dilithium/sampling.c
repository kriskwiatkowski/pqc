#include <stdint.h>
#include <stddef.h>

#include <stdio.h>
#include <assert.h>

// calculate number of bits used to encode 'v'
static inline uint8_t bitlen8(uint8_t v) {
	unsigned r = 8;
	while (!((v >> (r-1)) & 1) && --r) {}
	return r;
}


unsigned sampling_rej_eta(
    int32_t *out,
    size_t olen,
    const uint8_t *in,
    size_t isz,
    int8_t maxv) {

    const uint8_t maxv_log2 = bitlen8(maxv);
    const int32_t maxv_h = maxv>>1;
    const uint8_t mask = (1<<maxv_log2)-1;
    size_t oid = 0, bid = 0, c;
    uint32_t tmp;
    uint8_t y;

    while ((bid + 3 < isz) && (oid<olen)) {
        tmp = (uint32_t)in[bid+0] << 0 |
              (uint32_t)in[bid+1] << 8 |
              (uint32_t)in[bid+2] << 16|
              (uint32_t)in[bid+3] << 24;
        do {
            y = (tmp >> c) & mask;
            if (y < maxv) {
                out[oid++] = maxv_h - y;
            }
            c += maxv_log2;
        } while ((c+maxv_log2 < 8*sizeof tmp) && (oid < olen));
        bid += sizeof tmp;
        c = 0;
    }

    return oid;
}
