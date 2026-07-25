/* test_audit.c - audit emitter coverage */
#define _POSIX_C_SOURCE 200809L
#include "test_main.h"
#include "audit.h"
#include "truthimatics.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int test_audit_emits_json(void)
{
    ZP_TEST_BEGIN("audit_emits_json");
    struct zp_runtime rt;
    memset(&rt, 0, sizeof(rt));
    rt.uid = 1000;
    snprintf(rt.hostname, sizeof(rt.hostname), "testhost");
    snprintf(rt.kernel, sizeof(rt.kernel), "5.15.0 test");
    snprintf(rt.username, sizeof(rt.username), "tester");
    rt.chains[0] = zp_calloc(1, sizeof(struct zp_evidence_chain));
    zp_evidence_chain_init(rt.chains[0], "demo");
    snprintf(rt.probes[0], sizeof(rt.probes[0]), "demo");
    rt.probe_count = 1;
    zp_evidence_add(rt.chains[0], "D-1", "/bin/xyz", "demo", "fix",
                       0.9f, ZP_VERDICT_DETERMINISTIC,
                       ZP_SEV_CRITICAL);
    zp_engine_decide(rt.chains[0]);
    rt.max_risk_x10 = 90;
    snprintf(rt.risk_label, sizeof(rt.risk_label), "HIGH");
    struct audit_ctx ctx;
    audit_ctx_init(&ctx, 4, 32);
    audit_ctx_add_probe(&ctx, "demo", "DETERMINISTIC", 1, 9.5f);
    struct audit_finding f = {
        .id = "D-1", .target = "/bin/xyz",
        .description = "demo", .remediation = "fix",
        .weight = 0.9f, .severity = "CRITICAL", .risk_score = 9.5f
    };
    audit_ctx_add_finding(&ctx, 0, &f);
    FILE *out = tmpfile();
    int rc = audit_emit_json(&rt, out);
    ASSERT_EQ_INT(rc, ZP_OK);
    fseek(out, 0, SEEK_SET);
    char buf[8192];
    size_t n = fread(buf, 1, sizeof(buf) - 1, out);
    buf[n] = '\0';
    ASSERT_TRUE(strstr(buf, "z-privesc.audit/v1") != NULL);
    ASSERT_TRUE(strstr(buf, "\"DETERMINISTIC\"") != NULL);
    ASSERT_TRUE(strstr(buf, "\"CRITICAL\"") != NULL);
    fclose(out);
    zp_evidence_chain_release(rt.chains[0]);
    free(rt.chains[0]);
    audit_ctx_release(&ctx);
    ZP_TEST_END("audit_emits_json", 1);
    return ZP_TEST_PASS;
}

int test_audit_emits_html(void)
{
    ZP_TEST_BEGIN("audit_emits_html");
    struct zp_runtime rt;
    memset(&rt, 0, sizeof(rt));
    rt.uid = 1000;
    snprintf(rt.hostname, sizeof(rt.hostname), "h");
    snprintf(rt.kernel, sizeof(rt.kernel), "k");
    snprintf(rt.username, sizeof(rt.username), "u");
    rt.chains[0] = zp_calloc(1, sizeof(struct zp_evidence_chain));
    zp_evidence_chain_init(rt.chains[0], "demo");
    snprintf(rt.probes[0], sizeof(rt.probes[0]), "demo");
    rt.probe_count = 1;
    rt.max_risk_x10 = 50;
    snprintf(rt.risk_label, sizeof(rt.risk_label), "MEDIUM");
    struct audit_ctx ctx;
    audit_ctx_init(&ctx, 4, 32);
    audit_ctx_add_probe(&ctx, "demo", "REJECT", 0, 0.0f);
    FILE *out = tmpfile();
    int rc = audit_emit_html(&rt, out);
    ASSERT_EQ_INT(rc, ZP_OK);
    fseek(out, 0, SEEK_SET);
    char buf[2048];
    size_t n = fread(buf, 1, sizeof(buf) - 1, out);
    buf[n] = '\0';
    ASSERT_TRUE(strstr(buf, "<html>") != NULL);
    ASSERT_TRUE(strstr(buf, "Z-Privesc Audit") != NULL);
    fclose(out);
    zp_evidence_chain_release(rt.chains[0]);
    free(rt.chains[0]);
    audit_ctx_release(&ctx);
    ZP_TEST_END("audit_emits_html", 1);
    return ZP_TEST_PASS;
}

int test_audit_add_finding_resize(void)
{
    ZP_TEST_BEGIN("audit_add_finding_resize");
    struct audit_ctx ctx;
    audit_ctx_init(&ctx, 1, 1024);
    int idx = audit_ctx_add_probe(&ctx, "p", "REJECT", 0, 0.0f);
    ASSERT_EQ_INT(idx, 0);
    for (int i = 0; i < 100; i++) {
        struct audit_finding f = {
            .id = "x", .target = "/t", .description = "d",
            .remediation = "r", .weight = 0.1f,
            .severity = "LOW", .risk_score = 0.5f
        };
        int rc = audit_ctx_add_finding(&ctx, idx, &f);
        ASSERT_EQ_INT(rc, ZP_OK);
    }
    ASSERT_EQ_INT(ctx.probes[idx].finding_count, 100);
    audit_ctx_release(&ctx);
    ZP_TEST_END("audit_add_finding_resize", 1);
    return ZP_TEST_PASS;
}
