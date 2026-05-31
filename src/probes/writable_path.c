/*
 * writable_path.c - World-writable $PATH entry detector
 *
 * Parses the PATH environment variable (or the supplied fallback),
 * tests each directory for world-writability, and reports evidence
 * ranked by position.  Entries that appear before /usr/bin escalate
 * to HIGH; a bare "." in PATH escalates to CRITICAL.
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
#include <sys/stat.h>
#include <unistd.h>

static int position_priority(const char *dir)
{
    if (strcmp(dir, ".") == 0) {
        return 3;
    }
    if (strcmp(dir, "/bin") == 0 || strcmp(dir, "/sbin") == 0 ||
        strcmp(dir, "/usr/local/bin") == 0 || strcmp(dir, "/usr/bin") == 0) {
        return 2;
    }
    if (dir[0] == '/') {
        return 1;
    }
    return 1;
}

int zp_probe_writable_path(struct zp_evidence_chain *c, const char *root,
                              struct audit_ctx *ctx)
{
    (void)root;
    (void)ctx;
    if (c == NULL) {
        return ZP_ERR_INVAL;
    }
    const char *env = getenv("PATH");
    char       *buf = NULL;
    if (env == NULL || env[0] == '\0') {
        buf = zp_strdup("/usr/local/bin:/usr/bin:/bin");
        env = buf;
    } else {
        buf = zp_strdup(env);
        env = buf;
    }
    char  *save = NULL;
    char  *tok  = strtok_r(buf, ":", &save);
    int    n    = 0;
    while (tok != NULL) {
        n++;
        if (strcmp(tok, ".") == 0) {
            char id[ZP_EVIDENCE_ID_MAX];
            snprintf(id, sizeof(id), "WPATH-%03d", n);
            zp_evidence_add(c, id, ".",
                "Current directory '.' is in PATH; trivially hijackable",
                "Remove '.' from PATH for non-root users", 0.98f,
                ZP_VERDICT_DETERMINISTIC, ZP_SEV_CRITICAL);
            tok = strtok_r(NULL, ":", &save);
            continue;
        }
        struct stat st;
        if (stat(tok, &st) != 0) {
            tok = strtok_r(NULL, ":", &save);
            continue;
        }
        if (!S_ISDIR(st.st_mode)) {
            tok = strtok_r(NULL, ":", &save);
            continue;
        }
        if (st.st_mode & S_IWOTH) {
            int prio = position_priority(tok);
            float weight;
            enum zp_severity sev;
            if (prio >= 3) {
                weight = 0.98f;
                sev    = ZP_SEV_CRITICAL;
            } else if (prio >= 2) {
                weight = 0.9f;
                sev    = ZP_SEV_HIGH;
            } else {
                weight = 0.75f;
                sev    = ZP_SEV_HIGH;
            }
            char id[ZP_EVIDENCE_ID_MAX];
            snprintf(id, sizeof(id), "WPATH-%03d", n);
            char desc[ZP_DESC_MAX];
            snprintf(desc, sizeof(desc),
                     "World-writable PATH entry: %s (mode %04o)",
                     tok, st.st_mode & 0777);
            char rem[ZP_REMEDIATION_MAX];
            snprintf(rem, sizeof(rem),
                     "chmod o-w %s and audit ownership", tok);
            zp_evidence_add(c, id, tok, desc, rem, weight,
                              ZP_VERDICT_DETERMINISTIC, sev);
        }
        tok = strtok_r(NULL, ":", &save);
    }
    free(buf);
    return ZP_OK;
}
#define PATH_PRIORITY_BONUS  0.15f
