/* test_kernel_vuln.c */
#define _POSIX_C_SOURCE 200809L
#include "test_main.h"
#include "probes.h"
#include "audit.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int test_kernel_vuln_old_kernel(void)
{
    ZP_TEST_BEGIN("kernel_vuln_old_kernel");
    char tmp[] = "/tmp/zprivesc-proc-XXXXXX";
    char *root = mkdtemp(tmp);
    if (root == NULL) return ZP_TEST_SKIP;
    char proc[512], ver[512];
    snprintf(proc, sizeof(proc), "%s/proc", root);
    mkdir(proc, 0755);
    snprintf(ver, sizeof(ver), "%s/version", proc);
    FILE *f = fopen(ver, "w");
    if (f == NULL) {
        rmdir(proc);
        rmdir(root);
        return ZP_TEST_SKIP;
    }
    fprintf(f, "Linux version 3.13.0-100-generic (buildd@lcy01-amd64-030)\n");
    fclose(f);
    struct zp_evidence_chain c;
    zp_evidence_chain_init(&c, "kernel_vuln");
    struct audit_ctx ctx;
    audit_ctx_init(&ctx, 4, 32);
    int rc = zp_probe_kernel_vuln(&c, root, &ctx);
    ASSERT_EQ_INT(rc, ZP_OK);
    ASSERT_TRUE(c.count > 0);
    zp_evidence_chain_release(&c);
    audit_ctx_release(&ctx);
    unlink(ver);
    rmdir(proc);
    rmdir(root);
    ZP_TEST_END("kernel_vuln_old_kernel", 1);
    return ZP_TEST_PASS;
}

int test_kernel_vuln_new_kernel(void)
{
    ZP_TEST_BEGIN("kernel_vuln_new_kernel");
    char tmp[] = "/tmp/zprivesc-proc-XXXXXX";
    char *root = mkdtemp(tmp);
    if (root == NULL) return ZP_TEST_SKIP;
    char proc[512], ver[512];
    snprintf(proc, sizeof(proc), "%s/proc", root);
    mkdir(proc, 0755);
    snprintf(ver, sizeof(ver), "%s/version", proc);
    FILE *f = fopen(ver, "w");
    if (f == NULL) {
        rmdir(proc);
        rmdir(root);
        return ZP_TEST_SKIP;
    }
    fprintf(f, "Linux version 99.99.99-generic (build)\n");
    fclose(f);
    struct zp_evidence_chain c;
    zp_evidence_chain_init(&c, "kernel_vuln");
    struct audit_ctx ctx;
    audit_ctx_init(&ctx, 4, 32);
    int rc = zp_probe_kernel_vuln(&c, root, &ctx);
    ASSERT_EQ_INT(rc, ZP_OK);
    bool clean = false;
    for (struct zp_evidence_link *l = c.head; l != NULL; l = l->next) {
        if (strstr(l->id, "KERN-CLEAN") != NULL) clean = true;
    }
    ASSERT_TRUE(clean);
    zp_evidence_chain_release(&c);
    audit_ctx_release(&ctx);
    unlink(ver);
    rmdir(proc);
    rmdir(root);
    ZP_TEST_END("kernel_vuln_new_kernel", 1);
    return ZP_TEST_PASS;
}

int test_kernel_vuln_handles_garbage(void)
{
    ZP_TEST_BEGIN("kernel_vuln_handles_garbage");
    char tmp[] = "/tmp/zprivesc-proc-XXXXXX";
    char *root = mkdtemp(tmp);
    if (root == NULL) return ZP_TEST_SKIP;
    char proc[512], ver[512];
    snprintf(proc, sizeof(proc), "%s/proc", root);
    mkdir(proc, 0755);
    snprintf(ver, sizeof(ver), "%s/version", proc);
    FILE *f = fopen(ver, "w");
    if (f == NULL) {
        rmdir(proc);
        rmdir(root);
        return ZP_TEST_SKIP;
    }
    fprintf(f, "non-sense no version here\n");
    fclose(f);
    struct zp_evidence_chain c;
    zp_evidence_chain_init(&c, "kernel_vuln");
    struct audit_ctx ctx;
    audit_ctx_init(&ctx, 4, 32);
    int rc = zp_probe_kernel_vuln(&c, root, &ctx);
    ASSERT_EQ_INT(rc, ZP_OK);
    zp_evidence_chain_release(&c);
    audit_ctx_release(&ctx);
    unlink(ver);
    rmdir(proc);
    rmdir(root);
    ZP_TEST_END("kernel_vuln_handles_garbage", 1);
    return ZP_TEST_PASS;
}
