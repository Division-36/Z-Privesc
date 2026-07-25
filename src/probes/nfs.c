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
        char *host_spec = strtok(NULL, " \t");
        if (path == NULL || host_spec == NULL) continue;
        /* Parse host_spec which may be "*(", "*(options)", or just "*" */
        char host_buf[256];
        char opts_buf[512];
        opts_buf[0] = '\0';
        char *paren = strchr(host_spec, '(');
        if (paren != NULL) {
            /* host_spec = "*(no_root_squash,rw)" format */
            size_t hlen = (size_t)(paren - host_spec);
            if (hlen >= sizeof(host_buf)) hlen = sizeof(host_buf) - 1;
            memcpy(host_buf, host_spec, hlen);
            host_buf[hlen] = '\0';
            /* Extract options from inside parentheses */
            char *close_p = strchr(paren + 1, ')');
            if (close_p != NULL) {
                size_t olen = (size_t)(close_p - paren - 1);
                if (olen >= sizeof(opts_buf)) olen = sizeof(opts_buf) - 1;
                memcpy(opts_buf, paren + 1, olen);
                opts_buf[olen] = '\0';
            }
        } else {
            strncpy(host_buf, host_spec, sizeof(host_buf) - 1);
            host_buf[sizeof(host_buf) - 1] = '\0';
            /* Read remaining tokens as options */
            char *rest_tok;
            while ((rest_tok = strtok(NULL, " \t")) != NULL) {
                if (opts_buf[0] != '\0') {
                    size_t len = strlen(opts_buf);
                    if (len + 1 < sizeof(opts_buf)) {
                        opts_buf[len] = ' ';
                        opts_buf[len + 1] = '\0';
                    }
                }
                strncat(opts_buf, rest_tok, sizeof(opts_buf) - strlen(opts_buf) - 2);
            }
        }
        bool world     = (strcmp(host_buf, "*") == 0);
        bool insecure  = (strstr(opts_buf, "insecure") != NULL);
        bool no_root   = (strstr(opts_buf, "no_root_squash") != NULL);
        bool rw        = (strstr(opts_buf, "rw") != NULL &&
                          strstr(opts_buf, "ro") == NULL);
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
