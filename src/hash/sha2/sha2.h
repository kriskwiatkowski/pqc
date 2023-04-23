#include <stdbool.h>
#include <stdint.h>
#include "common/utils.h"

// Supported sha2 algorithms
typedef enum {
	#define PQC_SHA2_W64 10U

	PQC_SHA2_224,
	PQC_SHA2_256,
	PQC_SHA2_384 = PQC_SHA2_W64,
	PQC_SHA2_512,
} pqc_sha2_algs_t;

// API

// Stores initial values H_0
struct H_t {
	union {
		uint32_t h32[8];
		uint64_t h64[8];
	} h;
};

struct pqc_sha2_t {
	bool w32;
	bool done;
	struct H_t h0;
	size_t digest_sz;
};

bool pqc_sha2_init(
	struct pqc_sha2_t *ctx,
	pqc_sha2_algs_t alg);

bool pqc_sha2_update(
	struct pqc_sha2_t *ctx,
	const uint8_t *msg,
	size_t len);

bool pqc_sha2_sum(
	struct pqc_sha2_t *ctx,
	const uint8_t *msg,
	size_t len);
