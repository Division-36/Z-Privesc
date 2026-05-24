/* test_util.c - util coverage */
#define _POSIX_C_SOURCE 200809L
#include "test_main.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int test_util_path_join(void)
{
    ZP_TEST_BEGIN("util_path_join");
    char buf[64];
    ASSERT_EQ_INT(zp_path_join(buf, sizeof(buf), "/etc", "passwd"),
                  ZP_OK);
    ASSERT_STR_EQ(buf, "/etc/passwd");
    ASSERT_EQ_INT(zp_path_join(buf, sizeof(buf), "/etc/", "passwd"),
                  ZP_OK);
    ASSERT_STR_EQ(buf, "/etc/passwd");
    ASSERT_EQ_INT(zp_path_join(buf, 4, "/etc", "passwd"),
                  ZP_ERR_INVAL);
    ZP_TEST_END("util_path_join", 1);
    return ZP_TEST_PASS;
}

int test_util_path_normalize(void)
{
    ZP_TEST_BEGIN("util_path_normalize");
    char p1[] = "/etc/../etc/./passwd";
    ASSERT_EQ_INT(zp_path_normalize(p1), ZP_OK);
    ASSERT_STR_EQ(p1, "/etc/passwd");
    char p2[] = "foo/bar/..";
    ASSERT_EQ_INT(zp_path_normalize(p2), ZP_OK);
    ZP_TEST_END("util_path_normalize", 1);
    return ZP_TEST_PASS;
}

int test_util_hex_encode(void)
{
    ZP_TEST_BEGIN("util_hex_encode");
    uint8_t raw[] = { 0xde, 0xad, 0xbe, 0xef };
    char hex[16];
    ASSERT_EQ_INT(zp_hex_encode(raw, 4, hex, sizeof(hex)), ZP_OK);
    ASSERT_STR_EQ(hex, "deadbeef");
    ASSERT_EQ_INT(zp_hex_encode(raw, 4, hex, 4), ZP_ERR_INVAL);
    ZP_TEST_END("util_hex_encode", 1);
    return ZP_TEST_PASS;
}
