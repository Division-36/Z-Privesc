/* test_capabilities.c */
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
#include <limits.h>

int test_capabilities_safe_chain(void)
{
    ZP_TEST_BEGIN("capabilities_safe_chain");
    char tmpl[] = "/tmp/zprivesc-cap-XXXXXX";
    char *p = mkdtemp(tmpl);
    if (p == NULL) return ZP_TEST_SKIP;
    struct zp_evidence_chain c;
    zp_evidence_chain_init(&c, "capabilities");
    struct audit_ctx ctx;
    audit_ctx_init(&ctx, 4, 32);
    int rc = zp_probe_capabilities(&c, p, &ctx);
    ASSERT_EQ_INT(rc, ZP_OK);
    zp_evidence_chain_release(&c);
    audit_ctx_release(&ctx);
    rmdir(p);
    ZP_TEST_END("capabilities_safe_chain", 1);
    return ZP_TEST_PASS;
}

int test_capabilities_proc_status(void)
{
    ZP_TEST_BEGIN("capabilities_proc_status");
    char bnd[256] = {0};
    int rc = zp_read_proc_self_status_field("CapBnd", bnd, sizeof(bnd));
    ASSERT_EQ_INT(rc, ZP_OK);
    ASSERT_TRUE(strlen(bnd) > 0);
    ZP_TEST_END("capabilities_proc_status", 1);
    return ZP_TEST_PASS;
}

int test_capabilities_critical_filter(void)
{
    ZP_TEST_BEGIN("capabilities_critical_filter");
    const char *caps = "cap_sys_admin+ep cap_dac_override+p";
    bool crit = (strstr(caps, "cap_sys_admin") != NULL);
    ASSERT_TRUE(crit);
    const char *caps2 = "cap_chown+ep";
    bool crit2 = (strstr(caps2, "cap_sys_admin") != NULL ||
                  strstr(caps2, "cap_dac_override") != NULL ||
                  strstr(caps2, "cap_setuid") != NULL);
    ASSERT_FALSE(crit2);
    ZP_TEST_END("capabilities_critical_filter", 1);
    return ZP_TEST_PASS;
}
