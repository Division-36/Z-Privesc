/*
 * kernel_hardening.c - Kernel hardening settings probe
 *
 * Inspects /proc/sys values for ASLR, ptrace_scope, dmesg_restrict,
 * kptr_restrict, unprivileged_bpf_disabled, and other security
 * settings.  A disabled hardening setting that should be enabled is
 * a HIGH severity finding.
 *
 * Author: Zierax (Ziad Salah) <zs.01117875692@gmail.com>
 */

#define _POSIX_C_SOURCE 200809L

#include "z_privesc.h"
#include "probes.h"
#include "truthimatics.h"
#include "audit.h"
#include "util.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct hardening_check {
    const char *path;
    int         want;
    const char *description;
    float       weight;
    enum zp_severity sev;
};

static const struct hardening_check CHECKS[] = {
    { "/proc/sys/kernel/randomize_va_space", 2,
      "ASLR fully enabled (randomize_va_space=2)", 0.85f, ZP_SEV_HIGH },
    { "/proc/sys/kernel/yama/ptrace_scope",  1,
      "ptrace restricted to parent only", 0.7f, ZP_SEV_MEDIUM },
    { "/proc/sys/kernel/dmesg_restrict",     1,
      "dmesg restricted to CAP_SYSLOG", 0.7f, ZP_SEV_MEDIUM },
    { "/proc/sys/kernel/kptr_restrict",      2,
      "Kernel pointers hidden from non-root", 0.6f, ZP_SEV_MEDIUM },
    { "/proc/sys/kernel/unprivileged_bpf_disabled", 1,
      "Unprivileged BPF disabled", 0.85f, ZP_SEV_HIGH },
    { "/proc/sys/kernel/perf_event_paranoid", 3,
      "perf_event_paranoid >= 3 (hardened)", 0.5f, ZP_SEV_LOW },
    { "/proc/sys/kernel/kexec_load_disabled", 1,
      "kexec_load disabled", 0.6f, ZP_SEV_MEDIUM },
    { "/proc/sys/fs/protected_hardlinks",    1,
      "Hardlink protection enabled", 0.7f, ZP_SEV_MEDIUM },
    { "/proc/sys/fs/protected_symlinks",     1,
      "Symlink protection enabled", 0.7f, ZP_SEV_MEDIUM },
    { "/proc/sys/fs/suid_dumpable",          0,
      "suid_dumpable=0 (no core dumps from suid)", 0.7f, ZP_SEV_MEDIUM },
};

static int read_int(const char *path)
{
    FILE *f = fopen(path, "r");
    if (f == NULL) {
        return -1;
    }
    int v = -1;
    if (fscanf(f, "%d", &v) != 1) {
        v = -1;
    }
    fclose(f);
    return v;
}

int zp_probe_kernel_hardening(struct zp_evidence_chain *c,
                                  const char *root, struct audit_ctx *ctx)
{
    (void)ctx;
    if (c == NULL) {
        return ZP_ERR_INVAL;
    }
    const char *r = (root != NULL && root[0]) ? root : "/";
    size_t total = 0;
    size_t n = sizeof(CHECKS) / sizeof(CHECKS[0]);
    for (size_t i = 0; i < n; i++) {
        char p[ZP_PATH_MAX];
        const char *sub = CHECKS[i].path + strlen("/proc/");
        if (zp_path_join(p, sizeof(p), r, sub) != ZP_OK) {
            continue;
        }
        int got = read_int(p);
        if (got < 0) {
            continue;
        }
        if (got < CHECKS[i].want) {
            total++;
            char id[ZP_EVIDENCE_ID_MAX];
            snprintf(id, sizeof(id), "KHARD-%05zu", total);
            char desc[ZP_DESC_MAX];
            snprintf(desc, sizeof(desc),
                     "%s (got %d, want >= %d)",
                     CHECKS[i].description, got, CHECKS[i].want);
            char rem[ZP_REMEDIATION_MAX];
            snprintf(rem, sizeof(rem),
                     "Set %s to %d (write to <PATH>)",
                     CHECKS[i].path, CHECKS[i].want);
            zp_evidence_add(c, id, CHECKS[i].path, desc, rem,
                              CHECKS[i].weight,
                              ZP_VERDICT_DETERMINISTIC, CHECKS[i].sev);
        }
    }
    if (total == 0) {
        zp_evidence_add(c, "KHARD-CLEAN", "/proc/sys",
                           "All kernel hardening checks pass",
                           "No action required",
                           0.1f, ZP_VERDICT_REJECT, ZP_SEV_INFO);
    }
    return ZP_OK;
}
