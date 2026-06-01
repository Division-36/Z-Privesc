/*
 * sudoers.c - Sudoers misconfiguration detector
 *
 * Parses /etc/sudoers and /etc/sudoers.d entries for NOPASSWD, ALL,
 * dangerous target user rules.  Each rule is weighted by its
 * exploitability.  A user with NOPASSWD on ALL is CRITICAL.
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
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>

static bool current_user_matches(const char *spec)
{
    if (spec == NULL || spec[0] == '\0') {
        return false;
    }
    if (strcmp(spec, "ALL") == 0) {
        return true;
    }
    struct passwd *pw = getpwuid(getuid());
    if (pw == NULL) {
        return false;
    }
    if (strcmp(spec, pw->pw_name) == 0) {
        return true;
    }
    if (spec[0] == '%') {
        struct group *g = getgrnam(spec + 1);
        if (g != NULL) {
            for (char **m = g->gr_mem; *m != NULL; m++) {
                if (strcmp(*m, pw->pw_name) == 0) {
                    return true;
                }
            }
        }
    }
    return false;
}

static void parse_sudoers_file(struct zp_evidence_chain *c,
                               const char *path, size_t *total)
{
    FILE *f = fopen(path, "r");
    if (f == NULL) {
        return;
    }
    char line[1024];
    int  lineno = 0;
    while (fgets(line, sizeof(line), f) != NULL) {
        lineno++;
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\n' || *p == '\0') continue;
        if (strncmp(p, "Defaults", 8) == 0) continue;
        char *first = strtok(p, " \t");
        char *op    = strtok(NULL, " \t");
        char *spec  = strtok(NULL, " \t");
        if (first == NULL || op == NULL) continue;
        if (strcmp(op, "=") != 0 && strcmp(op, "(ALL)") != 0 &&
            strchr(op, '(') == NULL) {
            continue;
        }
        if (spec == NULL) spec = op;
        bool nopasswd = false;
        bool all      = false;
        if (strstr(first, "NOPASSWD") != NULL) nopasswd = true;
        if (strstr(first, "ALL") != NULL) all = true;
        if (spec && strstr(spec, "ALL") != NULL) all = true;
        if (!current_user_matches(first) && !all) continue;
        if (!nopasswd && !all) continue;
        (*total)++;
        char id[ZP_EVIDENCE_ID_MAX];
        snprintf(id, sizeof(id), "SUDO-%05zu", *total);
        char desc[ZP_DESC_MAX];
        snprintf(desc, sizeof(desc),
                 "Sudoers %s rule (line %d, op=%s)",
                 nopasswd ? "NOPASSWD" : "ALL",
                 lineno, op);
        char rem[ZP_REMEDIATION_MAX];
        snprintf(rem, sizeof(rem),
                 "Restrict rule in <PATH>; require authentication");
        float weight = (nopasswd && all) ? 0.95f : 0.6f;
        enum zp_severity sev = (nopasswd && all) ? ZP_SEV_CRITICAL
                                                    : ZP_SEV_HIGH;
        zp_evidence_add(c, id, path, desc, rem, weight,
                          ZP_VERDICT_DETERMINISTIC, sev);
    }
    fclose(f);
}

int zp_probe_sudoers(struct zp_evidence_chain *c, const char *root,
                        struct audit_ctx *ctx)
{
    (void)ctx;
    if (c == NULL) {
        return ZP_ERR_INVAL;
    }
    const char *r = (root != NULL && root[0]) ? root : "/";
    size_t total = 0;
    char p[ZP_PATH_MAX];
    if (zp_path_join(p, sizeof(p), r, "etc/sudoers") == ZP_OK) {
        parse_sudoers_file(c, p, &total);
    }
    char d[ZP_PATH_MAX];
    if (zp_path_join(d, sizeof(d), r, "etc/sudoers.d") == ZP_OK) {
        DIR *dir = NULL;
        if (zp_dir_open(&dir, d) == ZP_OK) {
            struct dirent *de;
            while ((de = readdir(dir)) != NULL) {
                if (strcmp(de->d_name, ".") == 0 ||
                    strcmp(de->d_name, "..") == 0) continue;
                char child[ZP_PATH_MAX];
                if (zp_path_join(child, sizeof(child), d,
                                    de->d_name) != ZP_OK) continue;
                parse_sudoers_file(c, child, &total);
            }
            zp_dir_close(dir);
        }
    }
    if (total == 0) {
        zp_evidence_add(c, "SUDO-CLEAN", "/etc/sudoers",
                           "No exploitable sudoers rules for current user",
                           "No action required",
                           0.1f, ZP_VERDICT_REJECT, ZP_SEV_INFO);
    }
    return ZP_OK;
}
#define SUDOERS_DROPIN_DIR "/etc/sudoers.d"
