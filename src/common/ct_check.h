#ifndef CT_CHECK_H
#define CT_CHECK_H

// helper
#define VOID(V) ((void)V)

// Uses Clang's Memory Sanitizer
#if defined(PQC_USE_CTSANITIZER) && defined(__clang__) && defined(__has_feature) && __has_feature(memory_sanitizer)
#include <stddef.h>
#include <sanitizer/msan_interface.h>
#elif defined(PQC_USE_CTGRIND)
#include <valgrind/valgrind.h>
#include <valgrind/memcheck.h>
#endif

// Set sz bytes of memory starting at address p as uninitialized. Switches on constat time checks.
static inline void ct_poison(const volatile void *p, size_t sz) {
#if defined(PQC_USE_CTSANITIZER) && defined(__clang__) && defined(__has_feature) && __has_feature(memory_sanitizer)
	__msan_allocated_memory(p,sz);
#elif defined(PQC_USE_CTGRIND)
	VALGRIND_MAKE_MEM_UNDEFINED(p,sz);
#else
	VOID(p), VOID(sz);
#endif
}

// Set sz bytes of memory starting at p as initialized. Switches off constat time checks.
static inline void ct_purify(const volatile void *p, size_t sz) {
#if defined(PQC_USE_CTSANITIZER) && defined(__clang__) && defined(__has_feature) && __has_feature(memory_sanitizer)
	__msan_unpoison(p,sz);
#elif defined(PQC_USE_CTGRIND)
	VALGRIND_MAKE_MEM_DEFINED(p,sz);
#else
	VOID(p), VOID(sz);
#endif
}

// Function instructs memory sanitizer that code expects to do operation on unintialized memory.
static inline void ct_expect_umr() {
#if defined(PQC_USE_CTSANITIZER) && defined(__clang__) && defined(__has_feature) && __has_feature(memory_sanitizer)
	__msan_set_expect_umr(1);
#endif
}

// Checks if action on unintialized memory has occured. If this is not a case
// then error is reported. It works in tandem with ct_expect_umr(). In current version of
// MSan, the code needs to be compiled with `-mllvm -msan-keep-going=1` flags in order to work
// correctly.
static inline void ct_require_umr() {
#if defined(PQC_USE_CTSANITIZER) && defined(__clang__) && defined(__has_feature) && __has_feature(memory_sanitizer)
	__msan_set_expect_umr(0);
#endif
}

#endif // CT_CHECK_H
