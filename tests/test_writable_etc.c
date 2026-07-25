/* test_writable_etc.c */
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

int test_writable_etc_clean(void)
{
    ZP_TEST_BEGIN("writable_etc_clean");
    char tmpl[] = "/tmp/zprivesc-etc-XXXXXX";
    char *p = mkdtemp(tmpl);
    if (p == NULL) return ZP_TEST_SKIP;
    char ed[768];
    snprintf(ed, sizeof(ed), "%s/etc", p);
    mkdir(ed, 0755);
    char f[768];
    snprintf(f, sizeof(f), "%s/passwd", ed);
    int fd = open(f, O_CREAT | O_WRONLY, 0644);
    if (fd >= 0) close(fd);
    struct zp_evidence_chain c;
    zp_evidence_chain_init(&c, "writable_etc");
    struct audit_ctx ctx;
    audit_ctx_init(&ctx, 4, 32);
    zp_probe_writable_etc(&c, p, &ctx);
    ASSERT_EQ_INT(c.count, 0);
    zp_evidence_chain_release(&c);
    audit_ctx_release(&ctx);
    unlink(f);
    rmdir(ed);
    rmdir(p);
    ZP_TEST_END("writable_etc_clean", 1);
    return ZP_TEST_PASS;
}

int test_writable_etc_detects_writable_file(void)
{
    ZP_TEST_BEGIN("writable_etc_detects_writable_file");
    char tmpl[] = "/tmp/zprivesc-etc-XXXXXX";
    char *p = mkdtemp(tmpl);
    if (p == NULL) return ZP_TEST_SKIP;
    char ed[768];
    snprintf(ed, sizeof(ed), "%s/etc", p);
    mkdir(ed, 0755);
    char f[768];
    snprintf(f, sizeof(f), "%s/passwd", ed);
    int fd = open(f, O_CREAT | O_WRONLY, 0666);
    if (fd >= 0) close(fd);
    chmod(f, 0666);
    struct zp_evidence_chain c;
    zp_evidence_chain_init(&c, "writable_etc");
    struct audit_ctx ctx;
    audit_ctx_init(&ctx, 4, 32);
    zp_probe_writable_etc(&c, p, &ctx);
    bool seen = false;
    for (struct zp_evidence_link *l = c.head; l != NULL; l = l->next) {
        if (strstr(l->target, "passwd") != NULL) {
            seen = true;
        }
    }
    ASSERT_TRUE(seen);
    zp_evidence_chain_release(&c);
    audit_ctx_release(&ctx);
    unlink(f);
    rmdir(ed);
    rmdir(p);
    ZP_TEST_END("writable_etc_detects_writable_file", 1);
    return ZP_TEST_PASS;
}

int test_writable_etc_detects_writable_dir(void)
{
    ZP_TEST_BEGIN("writable_etc_detects_writable_dir");
    char tmpl[] = "/tmp/zprivesc-etc-XXXXXX";
    char *p = mkdtemp(tmpl);
    if (p == NULL) return ZP_TEST_SKIP;
    char ed[768];
    snprintf(ed, sizeof(ed), "%s/etc", p);
    mkdir(ed, 0755);
    char d[768];
    snprintf(d, sizeof(d), "%s/sudoers.d", ed);
    mkdir(d, 0755);
    char f[768];
    snprintf(f, sizeof(f), "%s/weak", d);
    int fd = open(f, O_CREAT | O_WRONLY, 0666);
    if (fd >= 0) close(fd);
    chmod(f, 0666);
    struct zp_evidence_chain c;
    zp_evidence_chain_init(&c, "writable_etc");
    struct audit_ctx ctx;
    audit_ctx_init(&ctx, 4, 32);
    zp_probe_writable_etc(&c, p, &ctx);
    bool seen = false;
    for (struct zp_evidence_link *l = c.head; l != NULL; l = l->next) {
        if (strstr(l->target, "weak") != NULL) {
            seen = true;
        }
    }
    ASSERT_TRUE(seen);
    zp_evidence_chain_release(&c);
    audit_ctx_release(&ctx);
    unlink(f);
    rmdir(d);
    rmdir(ed);
    rmdir(p);
    ZP_TEST_END("writable_etc_detects_writable_dir", 1);
    return ZP_TEST_PASS;
}
