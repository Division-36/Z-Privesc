/*
 * test_main.c - Lightweight test framework + entry point
 *
 * Each test_XXX function is registered in the table at the bottom.
 * Run from the build directory: ./test_z_privesc
 *
 * Author: Zierax (Ziad Salah) <zs.01117875692@gmail.com>
 */

#define _POSIX_C_SOURCE 200809L

#include "z_privesc.h"
#include "truthimatics.h"
#include "risk.h"
#include "audit.h"
#include "util.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

struct test_case {
    const char *name;
    int        (*fn)(void);
};

#define ZP_TEST_PASS  0
#define ZP_TEST_FAIL  1
#define ZP_TEST_SKIP  77

static int g_fail = 0;
static int g_pass = 0;
static int g_skip = 0;

#define ZP_TEST_BEGIN(name)                                          \
    do {                                                                \
        fprintf(stderr, "  RUN   %s\n", (name));                       \
    } while (0)

#define ZP_TEST_END(name, ok)                                        \
    do {                                                                \
        if (ok) {                                                       \
            fprintf(stderr, "  OK    %s\n", (name));                   \
            g_pass++;                                                   \
        } else {                                                        \
            fprintf(stderr, "  FAIL  %s\n", (name));                   \
            g_fail++;                                                   \
        }                                                               \
    } while (0)

#define ASSERT_TRUE(cond)                                               \
    do {                                                                \
        if (!(cond)) {                                                  \
            fprintf(stderr, "    assertion failed: %s (%s:%d)\n",       \
                    #cond, __FILE__, __LINE__);                         \
            return ZP_TEST_FAIL;                                     \
        }                                                               \
    } while (0)

#define ASSERT_FALSE(cond) ASSERT_TRUE(!(cond))

#define ASSERT_EQ_INT(a, b)                                             \
    do {                                                                \
        long long _a = (long long)(a);                                  \
        long long _b = (long long)(b);                                  \
        if (_a != _b) {                                                 \
            fprintf(stderr, "    expected %lld got %lld (%s:%d)\n",     \
                    _b, _a, __FILE__, __LINE__);                        \
            return ZP_TEST_FAIL;                                     \
        }                                                               \
    } while (0)

#define ASSERT_NEAR(a, b, eps)                                          \
    do {                                                                \
        double _a = (double)(a);                                        \
        double _b = (double)(b);                                        \
        if (fabs(_a - _b) > (eps)) {                                    \
            fprintf(stderr, "    expected %.6f got %.6f (%s:%d)\n",     \
                    _b, _a, __FILE__, __LINE__);                        \
            return ZP_TEST_FAIL;                                     \
        }                                                               \
    } while (0)

#define ASSERT_STR_EQ(a, b)                                             \
    do {                                                                \
        const char *_a = (a);                                           \
        const char *_b = (b);                                           \
        if (_a == NULL || _b == NULL || strcmp(_a, _b) != 0) {          \
            fprintf(stderr, "    expected '%s' got '%s' (%s:%d)\n",     \
                    _b ? _b : "(null)", _a ? _a : "(null)",             \
                    __FILE__, __LINE__);                                \
            return ZP_TEST_FAIL;                                     \
        }                                                               \
    } while (0)

#include "test_cases.inc"

int main(void)
{
    zp_log_set_quiet(true);
    fprintf(stderr, "Z-Privesc test suite (%zu cases)\n",
            sizeof(TESTS) / sizeof(TESTS[0]));
    for (size_t i = 0; i < sizeof(TESTS) / sizeof(TESTS[0]); i++) {
        fprintf(stderr, "[%zu/%zu] %s\n",
                i + 1, sizeof(TESTS) / sizeof(TESTS[0]), TESTS[i].name);
        int rc = TESTS[i].fn();
        if (rc == ZP_TEST_SKIP) {
            fprintf(stderr, "  SKIP  %s\n", TESTS[i].name);
            g_skip++;
        } else if (rc == ZP_TEST_PASS) {
            fprintf(stderr, "  OK    %s\n", TESTS[i].name);
            g_pass++;
        } else {
            fprintf(stderr, "  FAIL  %s\n", TESTS[i].name);
            g_fail++;
        }
    }
    fprintf(stderr, "\nResult: %d passed, %d failed, %d skipped\n",
            g_pass, g_fail, g_skip);
    return g_fail == 0 ? 0 : 1;
}
