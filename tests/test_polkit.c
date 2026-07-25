/* test_polkit.c */
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

int test_polkit_missing_pieces(void)
{
    ZP_TEST_BEGIN("polkit_missing_pieces");
    struct zp_evidence_chain c;
    zp_evidence_chain_init(&c, "polkit");
    struct audit_ctx ctx;
    audit_ctx_init(&ctx, 4, 32);
    int rc = zp_probe_polkit(&c, "/", &ctx);
    ASSERT_EQ_INT(rc, ZP_OK);
    zp_evidence_chain_release(&c);
    audit_ctx_release(&ctx);
    ZP_TEST_END("polkit_missing_pieces", 1);
    return ZP_TEST_PASS;
}

int test_polkit_old_version_match(void)
{
    ZP_TEST_BEGIN("polkit_old_version_match");
    char tmpl[] = "/tmp/zprivesc-polkit-XXXXXX";
    char *root = mkdtemp(tmpl);
    if (root == NULL) return ZP_TEST_SKIP;
    char share[512], bin[512];
    snprintf(share, sizeof(share), "%s/usr/share/polkit-1", root);
    char version[512];
    snprintf(version, sizeof(version), "%s/version", share);
    FILE *f = fopen(version, "w");
    if (f == NULL) {
        rmdir(root);
        return ZP_TEST_SKIP;
    }
    fprintf(f, "0.96\n");
    fclose(f);
    snprintf(bin, sizeof(bin), "%s/usr/bin", root);
    mkdir(bin, 0755);
    snprintf(bin, sizeof(bin), "%s/usr/bin/pkexec", root);
    int fd = open(bin, O_CREAT | O_WRONLY, 0755);
    if (fd >= 0) close(fd);
    chmod(bin, 04755);
    struct zp_evidence_chain c;
    zp_evidence_chain_init(&c, "polkit");
    struct audit_ctx ctx;
    audit_ctx_init(&ctx, 4, 32);
    zp_probe_polkit(&c, root, &ctx);
    bool seen_cve = false;
    for (struct zp_evidence_link *l = c.head; l != NULL; l = l->next) {
        if (strstr(l->id, "CVE-2021-4034") != NULL) {
            seen_cve = true;
        }
    }
    ASSERT_TRUE(seen_cve);
    zp_evidence_chain_release(&c);
    audit_ctx_release(&ctx);
    unlink(bin);
    unlink(version);
    rmdir(share);
    rmdir(root);
    ZP_TEST_END("polkit_old_version_match", 1);
    return ZP_TEST_PASS;
}
