/*
 * nfs.c - NFS export misconfiguration detector
 *
 * Reads /etc/exports for world-exported filesystems and
 * no_root_squash options.  A no_root_squash export is a CRITICAL
 * finding because remote root maps to local root.
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

int zp_probe_nfs(struct zp_evidence_chain *c, const char *root,
                    struct audit_ctx *ctx)
{
    (void)ctx;
    if (c == NULL) {
        return ZP_ERR_INVAL;
    }
    const char *r = (root != NULL && root[0]) ? root : "/";
    char p[ZP_PATH_MAX];
    if (zp_path_join(p, sizeof(p), r, "etc/exports") != ZP_OK) {
        return ZP_OK;
    }
    FILE *f = fopen(p, "r");
    if (f == NULL) {
        zp_evidence_add(c, "NFS-NONE", "/etc/exports",
                           "No /etc/exports file",
                           "No action required",
                           0.1f, ZP_VERDICT_REJECT, ZP_SEV_INFO);
        return ZP_OK;
    }
    char line[1024];
    int  lineno = 0;
    size_t total = 0;
    while (fgets(line, sizeof(line), f) != NULL) {
        lineno++;
        char *hash = strchr(line, '#');
        if (hash != NULL) *hash = '\0';
        if (line[0] == '\n' || line[0] == '\0') continue;
        char *path = strtok(line, " \t");
        char *host = strtok(NULL, " \t");
        if (path == NULL || host == NULL) continue;
        char *rest = host + strlen(host) + 1;
        bool world     = (strcmp(host, "*") == 0);
        bool insecure  = (strstr(rest, "insecure") != NULL);
        bool no_root   = (strstr(rest, "no_root_squash") != NULL);
        bool rw        = (strstr(rest, "rw") != NULL &&
                          strstr(rest, "ro") == NULL);
        if (!world && !no_root && !insecure) continue;
        total++;
        char id[ZP_EVIDENCE_ID_MAX];
        snprintf(id, sizeof(id), "NFS-%05zu", total);
        char desc[ZP_DESC_MAX];
        snprintf(desc, sizeof(desc),
                 "NFS export: world=%s no_root_squash=%s insecure=%s rw=%s "
                 "(line %d)",
                 world ? "yes" : "no",
                 no_root ? "yes" : "no",
                 insecure ? "yes" : "no",
                 rw ? "yes" : "no", lineno);
        char rem[ZP_REMEDIATION_MAX];
        snprintf(rem, sizeof(rem),
                 "Restrict <PATH> in /etc/exports: remove '*' and "
                 "no_root_squash; require auth");
        float weight = (no_root && world) ? 0.99f : 0.6f;
        enum zp_severity sev = (no_root && world) ? ZP_SEV_CRITICAL
                                                    : ZP_SEV_HIGH;
        zp_evidence_add(c, id, path, desc, rem, weight,
                          ZP_VERDICT_DETERMINISTIC, sev);
    }
    fclose(f);
    if (total == 0) {
        zp_evidence_add(c, "NFS-CLEAN", "/etc/exports",
                           "No dangerous NFS exports",
                           "No action required",
                           0.1f, ZP_VERDICT_REJECT, ZP_SEV_INFO);
    }
    return ZP_OK;
}
#define NFS_EXPORTS_FILE "/etc/exports"
