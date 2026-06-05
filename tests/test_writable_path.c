/* test_writable_path.c */
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

int test_writable_path_detects_dot(void)
{
    ZP_TEST_BEGIN("writable_path_detects_dot");
    setenv("PATH", ".:/usr/bin:/bin", 1);
    struct zp_evidence_chain c;
    zp_evidence_chain_init(&c, "writable_path");
    struct audit_ctx ctx;
    audit_ctx_init(&ctx, 4, 32);
    zp_probe_writable_path(&c, "/", &ctx);
    bool seen_dot = false;
    for (struct zp_evidence_link *l = c.head; l != NULL; l = l->next) {
        if (l->severity == ZP_SEV_CRITICAL) {
            seen_dot = true;
        }
    }
    ASSERT_TRUE(seen_dot);
    zp_evidence_chain_release(&c);
    audit_ctx_release(&ctx);
    ZP_TEST_END("writable_path_detects_dot", 1);
    return ZP_TEST_PASS;
}

int test_writable_path_detects_world_writable(void)
{
    ZP_TEST_BEGIN("writable_path_detects_world_writable");
    char tmpl[] = "/tmp/zprivesc-wwpath-XXXXXX";
    char *p = mkdtemp(tmpl);
    if (p == NULL) return ZP_TEST_SKIP;
    chmod(p, 0777);
    char path[1024];
    snprintf(path, sizeof(path), "%s:/usr/bin", p);
    setenv("PATH", path, 1);
    struct zp_evidence_chain c;
    zp_evidence_chain_init(&c, "writable_path");
    struct audit_ctx ctx;
    audit_ctx_init(&ctx, 4, 32);
    zp_probe_writable_path(&c, "/", &ctx);
    bool seen = false;
    for (struct zp_evidence_link *l = c.head; l != NULL; l = l->next) {
        if (strstr(l->target, "zprivesc-wwpath") != NULL) {
            seen = true;
        }
    }
    ASSERT_TRUE(seen);
    zp_evidence_chain_release(&c);
    audit_ctx_release(&ctx);
    rmdir(p);
    ZP_TEST_END("writable_path_detects_world_writable", 1);
    return ZP_TEST_PASS;
}

int test_writable_path_handles_missing(void)
{
    ZP_TEST_BEGIN("writable_path_handles_missing");
    setenv("PATH", "/nonexistent/dir/12345:/usr/bin", 1);
    struct zp_evidence_chain c;
    zp_evidence_chain_init(&c, "writable_path");
    struct audit_ctx ctx;
    audit_ctx_init(&ctx, 4, 32);
    int rc = zp_probe_writable_path(&c, "/", &ctx);
    ASSERT_EQ_INT(rc, ZP_OK);
    zp_evidence_chain_release(&c);
    audit_ctx_release(&ctx);
    ZP_TEST_END("writable_path_handles_missing", 1);
    return ZP_TEST_PASS;
}

int test_writable_path_uses_tempdir(void)
{
    ZP_TEST_BEGIN("writable_path_uses_tempdir");
    unsetenv("PATH");
    struct zp_evidence_chain c;
    zp_evidence_chain_init(&c, "writable_path");
    struct audit_ctx ctx;
    audit_ctx_init(&ctx, 4, 32);
    int rc = zp_probe_writable_path(&c, "/", &ctx);
    ASSERT_EQ_INT(rc, ZP_OK);
    zp_evidence_chain_release(&c);
    audit_ctx_release(&ctx);
    ZP_TEST_END("writable_path_uses_tempdir", 1);
    return ZP_TEST_PASS;
}
#define TEST_PATH_CHMOD_MODE 0755
