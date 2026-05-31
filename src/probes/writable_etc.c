/*
 * writable_etc.c - Writable /etc authentication file detector
 *
 * Tests /etc/passwd, /etc/shadow, /etc/sudoers, /etc/group and
 * /etc/sudoers.d/ for world-writability.  A world-writable
 * authentication file is an immediate critical finding.
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
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>

static const char *AUTH_FILES[] = {
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/group",
    "/etc/gshadow",
    "/etc/sudoers.d",
};

int zp_probe_writable_etc(struct zp_evidence_chain *c,
                              const char *root, struct audit_ctx *ctx)
{
    (void)ctx;
    if (c == NULL) {
        return ZP_ERR_INVAL;
    }
    const char *r = (root != NULL && root[0]) ? root : "/";
    for (size_t i = 0; i < sizeof(AUTH_FILES) / sizeof(AUTH_FILES[0]);
         i++) {
        char path[ZP_PATH_MAX];
        if (zp_path_join(path, sizeof(path), r, AUTH_FILES[i] + 1) !=
                ZP_OK) {
            continue;
        }
        struct stat st;
        if (lstat(path, &st) != 0) {
            continue;
        }
        if (S_ISLNK(st.st_mode)) {
            continue;
        }
        if (st.st_mode & S_IWOTH) {
            char id[ZP_EVIDENCE_ID_MAX];
            snprintf(id, sizeof(id), "WETC-%03zu", i + 1);
            char desc[ZP_DESC_MAX];
            snprintf(desc, sizeof(desc),
                     "Authentication file is world-writable (mode %04o)",
                     st.st_mode & 0777);
            char rem[ZP_REMEDIATION_MAX];
            snprintf(rem, sizeof(rem),
                     "chmod o-w <PATH> and audit owner");
            zp_evidence_add(c, id, path, desc, rem, 0.99f,
                              ZP_VERDICT_DETERMINISTIC,
                              ZP_SEV_CRITICAL);
        }
        if (S_ISDIR(st.st_mode)) {
            DIR *d = NULL;
            if (zp_dir_open(&d, path) != ZP_OK) {
                continue;
            }
            struct dirent *de;
            int n = 0;
            while ((de = readdir(d)) != NULL) {
                if (strcmp(de->d_name, ".") == 0 ||
                    strcmp(de->d_name, "..") == 0) {
                    continue;
                }
                n++;
                char child[ZP_PATH_MAX];
                if (zp_path_join(child, sizeof(child), path,
                                    de->d_name) != ZP_OK) {
                    continue;
                }
                struct stat cst;
                if (lstat(child, &cst) != 0) {
                    continue;
                }
                if (cst.st_mode & S_IWOTH) {
                    char id2[ZP_EVIDENCE_ID_MAX];
                    snprintf(id2, sizeof(id2), "WETC-D-%03d", n);
                    char desc2[ZP_DESC_MAX];
                    snprintf(desc2, sizeof(desc2),
                             "Drop-in is world-writable (mode %04o)",
                             cst.st_mode & 0777);
                    char rem2[ZP_REMEDIATION_MAX];
                    snprintf(rem2, sizeof(rem2),
                             "chmod o-w <PATH>");
                    zp_evidence_add(c, id2, child, desc2, rem2, 0.95f,
                                      ZP_VERDICT_DETERMINISTIC,
                                      ZP_SEV_CRITICAL);
                }
            }
            zp_dir_close(d);
        }
    }
    return ZP_OK;
}
#define AUTH_FILES_COUNT (sizeof(AUTH_FILES) / sizeof(AUTH_FILES[0]))
