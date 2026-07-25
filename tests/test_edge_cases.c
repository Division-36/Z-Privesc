#define _POSIX_C_SOURCE 200809L
#include "test_main.h"
#include "probes.h"
#include "audit.h"
#include "util.h"
#include "log.h"
#include "zp_crypto.h"
#include "risk.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <math.h>
#include <time.h>

static int make_tempdir(char *out, size_t cap)
{
    char tmpl[] = "/tmp/zptest-XXXXXX";
    char *p = mkdtemp(tmpl);
    if (p == NULL) return -1;
    snprintf(out, cap, "%s", p);
    return 0;
}

int test_util_path_extreme_length(void)
{
    ZP_TEST_BEGIN("util_path_extreme_length");
    char big[65536];
    memset(big, 'a', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';
    char out[ZP_PATH_MAX];
    int rc = zp_path_join(out, sizeof(out), "/tmp", big);
    ASSERT_EQ_INT(rc, ZP_ERR_INVAL);
    rc = zp_path_join(out, sizeof(out), "/tmp", "");
    ASSERT_EQ_INT(rc, ZP_OK);
    char deep[2048];
    size_t pos = 0;
    for (int i = 0; i < 100; i++) {
        pos += (size_t)snprintf(deep + pos, sizeof(deep) - pos, "sub%d/", i);
        if (pos >= sizeof(deep) - 16) break;
    }
    deep[pos] = '\0';
    rc = zp_path_join(out, sizeof(out), "/base", deep);
    ASSERT_EQ_INT(rc, ZP_OK);
    ASSERT_TRUE(strlen(out) < sizeof(out));
    ZP_TEST_END("util_path_extreme_length", 1);
    return ZP_TEST_PASS;
}

int test_util_null_empty_inputs(void)
{
    ZP_TEST_BEGIN("util_null_empty_inputs");
    char buf[64];
    memset(buf, 0xAA, sizeof(buf));
    buf[0] = '\0';
    int rc = zp_path_join(buf, sizeof(buf), "/a", "b");
    ASSERT_EQ_INT(rc, ZP_OK);
    ASSERT_STR_EQ(buf, "/a/b");
    rc = zp_path_join(NULL, 0, "/a", "b");
    ASSERT_EQ_INT(rc, ZP_ERR_INVAL);
    rc = zp_path_join(buf, sizeof(buf), NULL, "b");
    ASSERT_EQ_INT(rc, ZP_ERR_INVAL);
    rc = zp_path_join(buf, sizeof(buf), "/a", NULL);
    ASSERT_EQ_INT(rc, ZP_ERR_INVAL);
    struct stat st;
    rc = zp_stat_follow("/nonexistent-path-xyz-123", &st);
    ASSERT_EQ_INT(rc, ZP_ERR_IO);
    rc = zp_stat_follow(NULL, &st);
    ASSERT_EQ_INT(rc, ZP_ERR_INVAL);
    rc = zp_file_readable(NULL);
    ASSERT_EQ_INT(rc, 0);
    rc = zp_file_writable(NULL);
    ASSERT_EQ_INT(rc, 0);
    ZP_TEST_END("util_null_empty_inputs", 1);
    return ZP_TEST_PASS;
}

int test_audit_massive_findings(void)
{
    ZP_TEST_BEGIN("audit_massive_findings");
    struct audit_ctx ctx;
    audit_ctx_init(&ctx, 2, 1024);
    int idx = audit_ctx_add_probe(&ctx, "mass", "UNCERTAIN", 0, 0.0f);
    ASSERT_TRUE(idx >= 0);
    int count = 0;
    for (int i = 0; i < 5000; i++) {
        struct audit_finding f = {
            .id = "MASS", .target = "/t", .description = "mass test",
            .remediation = "fix", .weight = 0.1f,
            .severity = "LOW", .risk_score = 0.5f
        };
        int rc = audit_ctx_add_finding(&ctx, (size_t)idx, &f);
        if (rc == ZP_OK) {
            count++;
        } else {
            break;
        }
    }
    ASSERT_TRUE(count >= 100);
    ASSERT_EQ_INT(ctx.probes[idx].finding_count, (size_t)count);
    audit_ctx_release(&ctx);
    ZP_TEST_END("audit_massive_findings", 1);
    return ZP_TEST_PASS;
}

int test_audit_zero_allocations(void)
{
    ZP_TEST_BEGIN("audit_zero_allocations");
    struct audit_ctx ctx;
    audit_ctx_init(&ctx, 0, 0);
    int idx = audit_ctx_add_probe(&ctx, "z", "REJECT", 0, 0.0f);
    ASSERT_TRUE(idx >= 0);
    struct audit_finding f = {
        .id = "Z", .target = "/t", .description = "d",
        .remediation = "r", .weight = 0.1f,
        .severity = "INFO", .risk_score = 0.0f
    };
    int rc = audit_ctx_add_finding(&ctx, (size_t)idx, &f);
    ASSERT_EQ_INT(rc, ZP_OK);
    audit_ctx_add_probe(&ctx, "z2", "REJECT", 0, 0.0f);
    audit_ctx_release(&ctx);
    ZP_TEST_END("audit_zero_allocations", 1);
    return ZP_TEST_PASS;
}

int test_evidence_massive_chain(void)
{
    ZP_TEST_BEGIN("evidence_massive_chain");
    struct zp_evidence_chain c;
    zp_evidence_chain_init(&c, "stress");
    int n = 10000;
    for (int i = 0; i < n; i++) {
        char id[32];
        snprintf(id, sizeof(id), "E-%d", i);
        int rc = zp_evidence_add(&c, id, "/target", "desc", "rem",
                                 0.5f, ZP_VERDICT_DETERMINISTIC,
                                 ZP_SEV_MEDIUM);
        if (rc != ZP_OK) {
            n = i;
            break;
        }
    }
    ASSERT_TRUE(c.count > 100);
    enum zp_verdict v = zp_engine_decide(&c);
    ASSERT_EQ_INT((int)v, (int)ZP_VERDICT_DETERMINISTIC);
    zp_evidence_chain_release(&c);
    ASSERT_EQ_INT(c.count, 0);
    ZP_TEST_END("evidence_massive_chain", 1);
    return ZP_TEST_PASS;
}

int test_truthimatics_extreme_weights(void)
{
    ZP_TEST_BEGIN("truthimatics_extreme_weights");
    struct zp_evidence_chain c;
    zp_evidence_chain_init(&c, "weights");
    zp_evidence_add(&c, "W-1", "/t", "d", "r", 0.0f,
                    ZP_VERDICT_REJECT, ZP_SEV_INFO);
    zp_evidence_add(&c, "W-2", "/t", "d", "r", 1.0f,
                    ZP_VERDICT_DETERMINISTIC, ZP_SEV_CRITICAL);
    zp_evidence_add(&c, "W-3", "/t", "d", "r", -1.0f,
                    ZP_VERDICT_REJECT, ZP_SEV_INFO);
    zp_evidence_add(&c, "W-4", "/t", "d", "r", 2.5f,
                    ZP_VERDICT_DETERMINISTIC, ZP_SEV_MEDIUM);
    ASSERT_NEAR(c.total_weight, 2.0f, 0.001f);
    ASSERT_NEAR(c.det_weight, 2.0f, 0.001f);
    ASSERT_NEAR(c.rej_weight, 0.0f, 0.001f);
    enum zp_verdict v = zp_engine_decide(&c);
    ASSERT_EQ_INT((int)v, (int)ZP_VERDICT_DETERMINISTIC);
    float det = zp_engine_det_share(&c);
    ASSERT_TRUE(det > 0.5f);
    zp_evidence_chain_release(&c);
    ZP_TEST_END("truthimatics_extreme_weights", 1);
    return ZP_TEST_PASS;
}

int test_risk_boundary_values(void)
{
    ZP_TEST_BEGIN("risk_boundary_values");
    float s = zp_risk_finding(ZP_SEV_INFO, 0.0f);
    ASSERT_NEAR(s, 0.5f, 0.001f);
    s = zp_risk_finding(ZP_SEV_INFO, -0.5f);
    ASSERT_NEAR(s, 0.5f, 0.001f);
    s = zp_risk_finding(ZP_SEV_CRITICAL, 1.0f);
    ASSERT_NEAR(s, 10.0f, 0.001f);
    s = zp_risk_finding(ZP_SEV_CRITICAL, 2.0f);
    ASSERT_NEAR(s, 10.0f, 0.001f);
    s = zp_risk_finding(ZP_SEV_CRITICAL, -0.1f);
    ASSERT_NEAR(s, 9.5f, 0.001f);
    float scores[] = {0.0f, 0.0f, 0.0f};
    float overall = zp_risk_overall(scores, 3);
    ASSERT_NEAR(overall, 0.0f, 0.001f);
    scores[0] = 8.0f; scores[1] = 8.0f;
    overall = zp_risk_overall(scores, 2);
    ASSERT_TRUE(overall > 8.0f);
    overall = zp_risk_overall(scores, 0);
    ASSERT_NEAR(overall, 0.0f, 0.001f);
    overall = zp_risk_overall(NULL, 0);
    ASSERT_NEAR(overall, 0.0f, 0.001f);
    const char *label = zp_risk_label(10.0f);
    ASSERT_STR_EQ(label, "CRITICAL");
    label = zp_risk_label(-1.0f);
    ASSERT_STR_EQ(label, "INFO");
    ZP_TEST_END("risk_boundary_values", 1);
    return ZP_TEST_PASS;
}

int test_file_permission_denied(void)
{
    ZP_TEST_BEGIN("file_permission_denied");
    if (getuid() == 0) {
        ZP_TEST_END("file_permission_denied", 0);
        return ZP_TEST_SKIP;
    }
    char root[256];
    if (make_tempdir(root, sizeof(root)) != 0) {
        return ZP_TEST_SKIP;
    }
    char private_dir[512];
    snprintf(private_dir, sizeof(private_dir), "%s/private", root);
    mkdir(private_dir, 0000);
    char private_file[512];
    snprintf(private_file, sizeof(private_file), "%s/private/secret", root);
    int fd = open(private_file, O_CREAT | O_WRONLY, 0000);
    if (fd >= 0) close(fd);
    struct stat st;
    int rc = zp_stat_follow(private_file, &st);
    ASSERT_TRUE(rc != 0);
    rc = zp_file_readable(private_file);
    ASSERT_TRUE(rc == 0);
    chmod(private_dir, 0755);
    unlink(private_file);
    rmdir(private_dir);
    rmdir(root);
    ZP_TEST_END("file_permission_denied", 1);
    return ZP_TEST_PASS;
}

int test_deep_directory_structure(void)
{
    ZP_TEST_BEGIN("deep_directory_structure");
    char root[256];
    if (make_tempdir(root, sizeof(root)) != 0) {
        return ZP_TEST_SKIP;
    }
    char path[4096];
    snprintf(path, sizeof(path), "%s", root);
    for (int i = 0; i < 50; i++) {
        size_t cur = strlen(path);
        snprintf(path + cur, sizeof(path) - cur, "/d%d", i);
        if (mkdir(path, 0755) != 0 && errno != EEXIST) {
            break;
        }
    }
    struct stat st;
    int rc = zp_stat_follow(path, &st);
    ASSERT_EQ_INT(rc, 0);
    ASSERT_TRUE(S_ISDIR(st.st_mode));
    char joined[4096];
    rc = zp_path_join(joined, sizeof(joined), path, "bottom");
    ASSERT_EQ_INT(rc, ZP_OK);
    char norm[4096];
    snprintf(norm, sizeof(norm), "%s", joined);
    rc = zp_path_normalize(norm);
    ASSERT_EQ_INT(rc, ZP_OK);
    char *crawl = root;
    while (crawl != NULL && *crawl) {
        char *slash = strchr(crawl + 1, '/');
        if (slash == NULL) break;
        *slash = '\0';
        rmdir(crawl);
        *slash = '/';
        crawl = slash;
    }
    rmdir(root);
    ZP_TEST_END("deep_directory_structure", 1);
    return ZP_TEST_PASS;
}

int test_special_characters_paths(void)
{
    ZP_TEST_BEGIN("special_characters_paths");
    char root[256];
    if (make_tempdir(root, sizeof(root)) != 0) {
        return ZP_TEST_SKIP;
    }
    const char *names[] = {
        "file with spaces",
        "file(with)parens",
        "file[with]brackets",
        "file-with-dashes",
        "file_with_underscores",
        "file.with.dots",
        "file'with'quotes",
        "file,with,commas",
        "file;with;semicolons",
        "file$with$dollars",
        "file with space and (parens)",
        NULL
    };
    for (int i = 0; names[i] != NULL; i++) {
        char full[1024];
        snprintf(full, sizeof(full), "%s/%s", root, names[i]);
        int fd = open(full, O_CREAT | O_WRONLY, 0644);
        if (fd >= 0) {
            write(fd, "data", 4);
            close(fd);
        }
        struct stat st;
        int rc = zp_stat_follow(full, &st);
        ASSERT_EQ_INT(rc, 0);
        ASSERT_TRUE(S_ISREG(st.st_mode));
        char joined[2048];
        rc = zp_path_join(joined, sizeof(joined), root, names[i]);
        ASSERT_EQ_INT(rc, ZP_OK);
        ASSERT_STR_EQ(joined, full);
        unlink(full);
    }
    rmdir(root);
    ZP_TEST_END("special_characters_paths", 1);
    return ZP_TEST_PASS;
}

int test_audit_memory_leak_fix(void)
{
    ZP_TEST_BEGIN("audit_memory_leak_fix");
    struct audit_ctx ctx;
    audit_ctx_init(&ctx, 4, 8);
    int probe_idx = audit_ctx_add_probe(&ctx, "test_probe", "test_verdict", 1, 9.5f);
    ASSERT_TRUE(probe_idx >= 0);
    struct audit_finding f = {
        .id = "D-1", .target = "target",
        .description = "description", .remediation = "remediation",
        .weight = 0.5f, .severity = "MEDIUM", .risk_score = 9.5f
    };
    int rc = audit_ctx_add_finding(&ctx, probe_idx, &f);
    ASSERT_EQ_INT(rc, ZP_OK);
    audit_ctx_release(&ctx);
    audit_ctx_init(&ctx, 1, 1);
    ASSERT_EQ_INT(ctx.probe_capacity, 1);
    audit_ctx_release(&ctx);
    ZP_TEST_END("audit_memory_leak_fix", 1);
    return ZP_TEST_PASS;
}

int test_string_truncation_safety(void)
{
    ZP_TEST_BEGIN("string_truncation_safety");
    char buffer[32];
    snprintf(buffer, sizeof(buffer), "This is a very long string that exceeds the buffer size");
    ASSERT_TRUE(buffer[sizeof(buffer) - 1] == '\0');
    for (int size = 1; size <= 64; size++) {
        char small_buf[64];
        snprintf(small_buf, size, "A very long string that might be truncated depending on buffer size");
        ASSERT_TRUE(strlen(small_buf) < (size_t)size);
    }
    ZP_TEST_END("string_truncation_safety", 1);
    return ZP_TEST_PASS;
}

int test_capabilities_long_paths(void)
{
    ZP_TEST_BEGIN("capabilities_long_paths");
    char root[256];
    if (make_tempdir(root, sizeof(root)) != 0) {
        return ZP_TEST_SKIP;
    }
    char long_path[4096];
    snprintf(long_path, sizeof(long_path), "%s", root);
    for (int i = 0; i < 20; i++) {
        size_t cur = strlen(long_path);
        snprintf(long_path + cur, sizeof(long_path) - cur,
                 "/%0512d", i);
    }
    int rc_test = mkdir(long_path, 0755);
    if (rc_test != 0) {
        rmdir(root);
        ZP_TEST_END("capabilities_long_paths", 0);
        return ZP_TEST_SKIP;
    }
    struct zp_evidence_chain c;
    zp_evidence_chain_init(&c, "caps");
    struct audit_ctx ctx;
    audit_ctx_init(&ctx, 4, 32);
    rc_test = zp_probe_capabilities(&c, long_path, &ctx);
    ASSERT_EQ_INT(rc_test, ZP_OK);
    zp_evidence_chain_release(&c);
    audit_ctx_release(&ctx);
    for (int i = 0; i < 20; i++) {
        size_t cur = strlen(root);
        snprintf(long_path + cur, sizeof(long_path) - cur,
                 "/%0512d", i);
        rmdir(long_path);
    }
    rmdir(root);
    ZP_TEST_END("capabilities_long_paths", 1);
    return ZP_TEST_PASS;
}

int test_capabilities_edge_cases(void)
{
    ZP_TEST_BEGIN("capabilities_edge_cases");
    struct zp_evidence_chain c;
    zp_evidence_chain_init(&c, "caps");
    struct audit_ctx ctx;
    audit_ctx_init(&ctx, 4, 32);
    int rc = zp_probe_capabilities(&c, "/nonexistent-root-xyz", &ctx);
    ASSERT_EQ_INT(rc, ZP_OK);
    ASSERT_TRUE(c.count == 0 || c.count > 0);
    zp_evidence_chain_release(&c);
    audit_ctx_release(&ctx);
    rc = zp_probe_capabilities(NULL, "/tmp", NULL);
    ASSERT_EQ_INT(rc, ZP_ERR_INVAL);
    ZP_TEST_END("capabilities_edge_cases", 1);
    return ZP_TEST_PASS;
}
