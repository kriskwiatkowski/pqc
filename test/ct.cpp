#include <algorithm>
#include <vector>
#include <gtest/gtest.h>
#include <pqc/pqc.h>

// #ifdef VALGRIND
// #include <valgrind/valgrind.h>
// #include <valgrind/memcheck.h>
// #define POISON(p,sz) VALGRIND_MAKE_MEM_UNDEFINED(p,sz)
// #endif

#ifdef PQC_MEMSAN
#include <sanitizer/msan_interface.h>
#define POISON(p,sz) __msan_poison(p,sz)
#endif


TEST(ConstantTime, Poisonner_Basic) {
	unsigned char x[8] = {0};
//gi	POISON(x, 4);
	if(x[5]) x[6] = x[5];
	//UNPOISON(x, 4);
}
