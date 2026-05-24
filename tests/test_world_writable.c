/* test_world_writable.c */
#define _POSIX_C_SOURCE 200809L
#include "test_main.h"
#include "probes.h"
#include "audit.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

int test_world_writable_clean(void)
{
    ZP_TEST_BEGIN("world_writable_clean");
    struct zp_evidence_chain c;
    zp_evidence_chain_init(&c, "world_writable");
    struct audit_ctx ctx;
    audit_ctx_init(&ctx, 4, 32);
    int rc = zp_probe_world_writable(&c, "/", &ctx);
    ASSERT_EQ_INT(rc, ZP_OK);
    zp_evidence_chain_release(&c);
    audit_ctx_release(&ctx);
    ZP_TEST_END("world_writable_clean", 1);
    return ZP_TEST_PASS;
}

int test_world_writable_sticky_bit(void)
{
    ZP_TEST_BEGIN("world_writable_sticky_bit");
    char tmpl[] = "/tmp/zprivesc-ww-XXXXXX";
    char *p = mkdtemp(tmpl);
    if (p == NULL) return ZP_TEST_SKIP;
    chmod(p, 0777);
    char path[1024];
    snprintf(path, sizeof(path), "TMPDIR=%s", p);
    putenv(path);
    struct zp_evidence_chain c;
    zp_evidence_chain_init(&c, "world_writable");
    struct audit_ctx ctx;
    audit_ctx_init(&ctx, 4, 32);
    int rc = zp_probe_world_writable(&c, "/", &ctx);
    ASSERT_EQ_INT(rc, ZP_OK);
    zp_evidence_chain_release(&c);
    audit_ctx_release(&ctx);
    rmdir(p);
    ZP_TEST_END("world_writable_sticky_bit", 1);
    return ZP_TEST_PASS;
}
