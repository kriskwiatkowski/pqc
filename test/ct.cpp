// Those tests work only with Clang and Memory Sanitizer

#include <gtest/gtest.h>
#include <common/ct_check.h>
#include <stdio.h>
// tests from https://github.com/agl/ctgrind/blob/master/test.c

void nothing(void) {
  printf("exiting...");
}

TEST(ConstantTime, CtGrind_Negative) {
    unsigned char a[16], b[16];
    unsigned i;
    memset(a, 42, 16);
    memset(b, 42, 16);

    CT_DYE(a, 16);
    for (i = 0; i < 16; i++) {
        CT_EXPECT_UMR();
        if (a[i] != b[i]) {
            break;
        }
        CT_REQUIRE_UMR();
    }

    CT_PURIFY(a, 16);
    // Ensure buffers are not optimized-out
    ASSERT_EQ(a[0], b[0]);
}

TEST(ConstantTime, CtGrind_Positive_NoAccess) {
    unsigned i;
    char result = 0;
    unsigned char a[16], b[16];
    memset(a, 42, sizeof(a));
    memset(b, 42, sizeof(b));

    CT_DYE(a, 16);

    for (i = 0; i < 16; i++) {
        result |= a[i] ^ b[i];
    }
    CT_PURIFY(a, 16);

    // Purify result, to allow check that otherwise
    // would be not constant-time.
    CT_PURIFY(&result, 1);
    ASSERT_EQ(result, 0);
}


TEST(ConstantTime, CtGrind_Negative_UseSecretAsIndex) {
    static const unsigned char tab[2] = {1, 0};
    unsigned char a[16];
    unsigned char result;
    memset(a, 42, sizeof(a));

    CT_DYE(a, 16);

    CT_EXPECT_UMR();
    result = tab[a[0] & 1];
    CT_REQUIRE_UMR();

    CT_PURIFY(a, 16);

    // Ensure variables are not optimized-out
    CT_PURIFY(&result, 1);
    ASSERT_EQ(result, 1);
}
