/*
 * kernel_vuln.c - Kernel version CVE matcher
 *
 * Reads /proc/version, parses the major.minor.patch triple, and
 * matches against a built-in table of well-known privilege-escalation
 * CVEs.  The table is intentionally conservative: only CVEs with
 * public, weaponised exploits and high reliability are listed.
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
#include <ctype.h>

struct kernel_cve {
    const char *cve;
    const char *name;
    int         min_maj, min_min, min_patch;
    int         max_maj, max_min, max_patch;
    enum zp_severity sev;
    float       weight;
};

static const struct kernel_cve CVES[] = {
    { "CVE-2016-5195", "Dirty COW (mm/gup.c PTRACE race)",
      2,  0,  0,  4,  8,  3,  ZP_SEV_CRITICAL, 0.95f },
    { "CVE-2022-0847", "Dirty Pipe (pipe buffer flag leak)",
      3,  0,  0,  5, 16, 11, ZP_SEV_CRITICAL, 0.95f },
    { "CVE-2022-2588", "Linux kernel cls_route UAF",
      0,  0,  0,  5, 19,  0, ZP_SEV_HIGH,     0.75f },
    { "CVE-2023-0386", "OverlayFS FUSE capability leak",
      0,  0,  0,  6,  2,  0, ZP_SEV_HIGH,     0.7f  },
    { "CVE-2023-32233","Netfilter UAF (GameOver(lay))",
      0,  0,  0,  6,  3,  0, ZP_SEV_HIGH,     0.7f  },
    { "CVE-2023-2640", "OverlayFS privilege escalation",
      0,  0,  0,  6,  3,  0, ZP_SEV_HIGH,     0.7f  },
    { "CVE-2024-1086", "nf_tables UAF (local privilege escalation)",
      0,  0,  0,  6,  6,  0, ZP_SEV_HIGH,     0.6f  },
};
#define CVE_COUNT (sizeof(CVES) / sizeof(CVES[0]))

static int version_less_eq(int ma, int mi, int pa,
                           int mb, int mb_mi, int mb_pa)
{
    if (ma != mb) return ma < mb;
    if (mi != mb_mi) return mi < mb_mi;
    return pa <= mb_pa;
}

static int parse_uname(const char *v, int *maj, int *min, int *patch)
{
    const char *p = v;
    while (*p && !isdigit((unsigned char)*p)) p++;
    if (*p == '\0') return -1;
    return sscanf(p, "%d.%d.%d", maj, min, patch) == 3 ? 0 : -1;
}

int zp_probe_kernel_vuln(struct zp_evidence_chain *c,
                             const char *root, struct audit_ctx *ctx)
{
    (void)ctx;
    if (c == NULL || root == NULL) {
        return ZP_ERR_INVAL;
    }
    char buf[512];
    char procpath[ZP_PATH_MAX];
    if (zp_path_join(procpath, sizeof(procpath), root, "proc/version")
            != ZP_OK) {
        return ZP_OK;
    }
    FILE *f = fopen(procpath, "r");
    if (f == NULL) {
        return ZP_OK;
    }
    if (fgets(buf, sizeof(buf), f) == NULL) {
        fclose(f);
        return ZP_OK;
    }
    fclose(f);
    size_t l = strlen(buf);
    while (l > 0 && (buf[l - 1] == '\n' || buf[l - 1] == '\r')) {
        buf[--l] = '\0';
    }
    int maj = 0, min = 0, patch = 0;
    if (parse_uname(buf, &maj, &min, &patch) != 0) {
        return ZP_OK;
    }
    int matched = 0;
    for (size_t i = 0; i < CVE_COUNT; i++) {
        const struct kernel_cve *k = &CVES[i];
        if (version_less_eq(maj, min, patch,
                            k->max_maj, k->max_min, k->max_patch) &&
            version_less_eq(k->min_maj, k->min_min, k->min_patch,
                            maj, min, patch)) {
            matched++;
            char id[ZP_EVIDENCE_ID_MAX];
            snprintf(id, sizeof(id), "KERN-%s",
                     k->cve + 4);
            char desc[ZP_DESC_MAX];
            snprintf(desc, sizeof(desc),
                     "Kernel %d.%d.%d may be vulnerable to %s (%s)",
                     maj, min, patch, k->cve, k->name);
            char rem[ZP_REMEDIATION_MAX];
            snprintf(rem, sizeof(rem),
                     "Upgrade kernel to a patched release; "
                     "track %s for vendor backport status", k->cve);
            zp_evidence_add(c, id, buf, desc, rem, k->weight,
                              ZP_VERDICT_DETERMINISTIC, k->sev);
        }
    }
    if (matched == 0) {
        char id[ZP_EVIDENCE_ID_MAX];
        snprintf(id, sizeof(id), "KERN-CLEAN");
        char desc[ZP_DESC_MAX];
        snprintf(desc, sizeof(desc),
                 "Kernel %d.%d.%d matches no known high-impact CVEs",
                 maj, min, patch);
        zp_evidence_add(c, id, buf, desc, "No action required",
                           0.1f, ZP_VERDICT_REJECT, ZP_SEV_INFO);
    }
    return ZP_OK;
}
#define CVE_TABLE_MAX 20
