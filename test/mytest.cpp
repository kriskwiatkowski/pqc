#include <gtest/gtest.h>
#include "capi/pqapi.h"

extern const kem_params_t kems[];

// TODO: change - just to see if function registration works OK.
TEST(Kyber,XXX) {
	ASSERT_EQ(kems[0].p.prv_key_bsz, 1632);
}