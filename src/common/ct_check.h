#ifndef CT_CHECK_H
#define CT_CHECK_H

// Uses Clang's Memory Sanitizer
#if defined(PQC_USE_CTSANITIZER)
#if defined(__clang__) && defined(__has_feature) && __has_feature(memory_sanitizer)
#include <sanitizer/msan_interface.h>
// Set sz bytes of memory starting at x as uninitialized. Switches on
// constat time checks.
#define CT_DYE(x,sz) __msan_allocated_memory(x,sz)
// Set sz bytes of memory starting at x as initialized. Switches off
// constat time checks.
#define CT_PURIFY(x, sz) __msan_unpoison(x, sz)
// This macro is useful for testing. It instructs memory sanitizer
// that code expects to do reads from unintialized memory.
#define CT_EXPECT_UMR() __msan_set_expect_umr(1)
// This macro works in tandem with CT_EXPECT_UMR. It checks if
// unintialized memory read has occured, if not, it will report
// an error. In current version, code needs to be compiled
// with `-mllvm -msan-keep-going=1` flags in order to work
// correctly (otherwise, runtime will be stopped between
// macros with message "Existing").
#define CT_REQUIRE_UMR() __msan_set_expect_umr(0)
#else
#error("Clang is required to use CT_SANITIZER.")
#endif
// Uses Valgrind's Memcheck (aka ctgrind)
#elif defined(PQC_USE_CTGRIND)
#include <valgrind/valgrind.h>
#include <valgrind/memcheck.h>
// Set sz bytes of memory starting at x as uninitialized. Switches on
// constat time checks.
#define CT_DYE(p,sz) VALGRIND_MAKE_MEM_UNDEFINED(p,sz)
// Set sz bytes of memory starting at x as initialized. Switches off
// constat time checks.
#define CT_PURIFY(p,sz) VALGRIND_MAKE_MEM_DEFINED(p,sz)
// Not supported in Valgrind
#define CT_EXPECT_UMR()
// Not supported in Valgrind
#define CT_REQUIRE_UMR()

#elif // no ct-checks
#define CT_DYE(x,sz)
#define CT_PURIFY(x, sz)
#define CT_EXPECT_UMR()
#define CT_REQUIRE_UMR()
#endif // defined(__clang__) && defined(__has_feature) && __has_feature(memory_sanitizer)

#endif // CT_CHECK_H
