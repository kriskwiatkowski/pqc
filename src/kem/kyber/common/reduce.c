#include "params.h"
#include "reduce.h"
#include <stdint.h>

/*************************************************
* Name:        kyber_montgomery_reduce
*
* Description: Montgomery reduction; given a 32-bit integer a, computes
*              16-bit integer congruent to a * R^-1 mod q, where R=2^16
*
* Arguments:   - int32_t a: input integer to be reduced;
*                           has to be in {-q2^15,...,q2^15-1}
*
* Returns:     integer in {-q+1,...,q-1} congruent to a * R^-1 modulo q.
**************************************************/
int16_t kyber_montgomery_reduce(int32_t a) {
    int32_t t;
    int16_t u;

    u = (int16_t)(a * (int64_t)QINV);
    t = (int32_t)u * KYBER_Q;
    t = a - t;
    t >>= 16;
    return (int16_t)t;
}

/*************************************************
* Name:        kyber_barrett_reduce
*
* Description: Barrett reduction; given a 16-bit integer a, computes
*              centered representative congruent to a mod q in {0,q}
*
* Arguments:   - int16_t a: input integer to be reduced
*
* Returns:     integer in {0,q} congruent to a modulo q.
**************************************************/
int16_t kyber_barrett_reduce(int16_t a) {
    int16_t t;
    static const int32_t v = 20159;
    t  = ((v * a) + (1 << 25)) >> 26;
    return a - (t*KYBER_Q);
}
