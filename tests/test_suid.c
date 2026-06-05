/* test_suid.c */
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

static int make_root(char *out, size_t cap)
{
    char tmpl[] = "/tmp/zprivesc-suid-XXXXXX";
    char *p = mkdtemp(tmpl);
    if (p == NULL) return -1;
    snprintf(out, cap, "%s", p);
    return 0;
}

int test_suid_finds_fake_suid(void)
{
    ZP_TEST_BEGIN("suid_finds_fake_suid");
    char root[256];
    if (make_root(root, sizeof(root)) != 0) {
        return ZP_TEST_SKIP;
    }
    char bin[512];
    snprintf(bin, sizeof(bin), "%s/bash-fake", root);
    int fd = open(bin, O_CREAT | O_WRONLY, 0755);
    if (fd >= 0) {
        const char *content = "#!/bin/sh\necho hi\n";
        write(fd, content, strlen(content));
        close(fd);
    }
    chmod(bin, 04755);
    chown(bin, 0, 0);
    struct stat st;
    if (lstat(bin, &st) != 0 || (st.st_mode & S_ISUID) == 0) {
        unlink(bin);
        rmdir(root);
        ZP_TEST_END("suid_finds_fake_suid", 0);
        return ZP_TEST_SKIP;
    }
    struct zp_evidence_chain c;
    zp_evidence_chain_init(&c, "suid");
    struct audit_ctx ctx;
    audit_ctx_init(&ctx, 4, 32);
    int rc = zp_probe_suid(&c, root, &ctx);
    if (getuid() != 0) {
        chown(bin, getuid(), getgid());
    }
    ASSERT_EQ_INT(rc, ZP_OK);
    ASSERT_TRUE(c.count >= 1);
    zp_evidence_chain_release(&c);
    audit_ctx_release(&ctx);
    unlink(bin);
    rmdir(root);
    ZP_TEST_END("suid_finds_fake_suid", 1);
    return ZP_TEST_PASS;
}

int test_suid_ignores_symlink(void)
{
    ZP_TEST_BEGIN("suid_ignores_symlink");
    char root[256];
    if (make_root(root, sizeof(root)) != 0) {
        return ZP_TEST_SKIP;
    }
    char real[512], link[512];
    snprintf(real, sizeof(real), "%s/real", root);
    snprintf(link, sizeof(link), "%s/link", root);
    int fd = open(real, O_CREAT | O_WRONLY, 0755);
    if (fd >= 0) {
        write(fd, "x", 1);
        close(fd);
    }
    chmod(real, 04755);
    symlink(real, link);
    struct zp_evidence_chain c;
    zp_evidence_chain_init(&c, "suid");
    struct audit_ctx ctx;
    audit_ctx_init(&ctx, 4, 32);
    zp_probe_suid(&c, root, &ctx);
    bool seen_link = false;
    for (struct zp_evidence_link *l = c.head; l != NULL; l = l->next) {
        if (strstr(l->target, "/link") != NULL) {
            seen_link = true;
        }
    }
    ASSERT_FALSE(seen_link);
    zp_evidence_chain_release(&c);
    audit_ctx_release(&ctx);
    unlink(link);
    unlink(real);
    rmdir(root);
    ZP_TEST_END("suid_ignores_symlink", 1);
    return ZP_TEST_PASS;
}

int test_suid_empty_root(void)
{
    ZP_TEST_BEGIN("suid_empty_root");
    char root[256];
    if (make_root(root, sizeof(root)) != 0) {
        return ZP_TEST_SKIP;
    }
    struct zp_evidence_chain c;
    zp_evidence_chain_init(&c, "suid");
    struct audit_ctx ctx;
    audit_ctx_init(&ctx, 4, 32);
    zp_probe_suid(&c, root, &ctx);
    ASSERT_EQ_INT(c.count, 0);
    zp_evidence_chain_release(&c);
    audit_ctx_release(&ctx);
    rmdir(root);
    ZP_TEST_END("suid_empty_root", 1);
    return ZP_TEST_PASS;
}

int test_suid_dangerous_basename(void)
{
    ZP_TEST_BEGIN("suid_dangerous_basename");
    char root[256];
    if (make_root(root, sizeof(root)) != 0) {
        return ZP_TEST_SKIP;
    }
    char bin[512];
    snprintf(bin, sizeof(bin), "%s/nmap", root);
    int fd = open(bin, O_CREAT | O_WRONLY, 0755);
    if (fd >= 0) {
        write(fd, "x", 1);
        close(fd);
    }
    chmod(bin, 04755);
    struct zp_evidence_chain c;
    zp_evidence_chain_init(&c, "suid");
    struct audit_ctx ctx;
    audit_ctx_init(&ctx, 4, 32);
    zp_probe_suid(&c, root, &ctx);
    bool seen_dangerous = false;
    for (struct zp_evidence_link *l = c.head; l != NULL; l = l->next) {
        if (l->severity == ZP_SEV_CRITICAL) {
            seen_dangerous = true;
        }
    }
    ASSERT_TRUE(seen_dangerous);
    zp_evidence_chain_release(&c);
    audit_ctx_release(&ctx);
    unlink(bin);
    rmdir(root);
    ZP_TEST_END("suid_dangerous_basename", 1);
    return ZP_TEST_PASS;
}
#define TEST_SUID_SKIP_WSL 1
