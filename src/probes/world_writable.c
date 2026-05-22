/*
 * world_writable.c - World-writable sensitive file & sticky-bit probe
 *
 * Scans a curated set of sensitive directories (/etc, /root, /home,
 * /opt, /var, /usr/local) for world-writable regular files and
 * confirms the sticky bit on /tmp and /dev/shm.
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
#include <errno.h>

#define WW_MAX_DEPTH         3
#define WW_MAX_FINDINGS      4096

static const char *SENSITIVE_DIRS[] = {
    "/etc", "/root", "/home", "/opt", "/var", "/usr/local",
    "/usr/local/etc", "/srv"
};
static const char *STICKY_DIRS[] = {
    "/tmp", "/dev/shm", "/var/tmp"
};

static bool is_under(const char *path, const char *parent)
{
    size_t pl = strlen(parent);
    if (strncmp(path, parent, pl) != 0) return false;
    if (path[pl] == '\0' || path[pl] == '/') return true;
    return false;
}

static int scan_dir(const char *path, int depth,
                    struct zp_evidence_chain *c, size_t *total)
{
    DIR *d = NULL;
    if (zp_dir_open(&d, path) != ZP_OK) {
        return ZP_OK;
    }
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (*total >= WW_MAX_FINDINGS) break;
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) {
            continue;
        }
        char child[ZP_PATH_MAX];
        if (zp_path_join(child, sizeof(child), path, de->d_name) !=
                ZP_OK) {
            continue;
        }
        struct stat st;
        if (lstat(child, &st) != 0) continue;
        if (S_ISLNK(st.st_mode)) continue;
        if (S_ISDIR(st.st_mode)) {
            if (depth + 1 < WW_MAX_DEPTH) {
                scan_dir(child, depth + 1, c, total);
            }
            continue;
        }
        if (!S_ISREG(st.st_mode)) continue;
        if (!(st.st_mode & S_IWOTH)) continue;
        (*total)++;
        bool in_etc   = is_under(child, "/etc");
        bool in_root  = is_under(child, "/root");
        bool in_usr   = is_under(child, "/usr/local") ||
                        is_under(child, "/opt");
        float weight;
        enum zp_severity sev;
        if (in_etc) {
            weight = 0.95f;
            sev    = ZP_SEV_CRITICAL;
        } else if (in_root) {
            weight = 0.85f;
            sev    = ZP_SEV_HIGH;
        } else if (in_usr) {
            weight = 0.7f;
            sev    = ZP_SEV_MEDIUM;
        } else {
            weight = 0.5f;
            sev    = ZP_SEV_LOW;
        }
        char id[ZP_EVIDENCE_ID_MAX];
        snprintf(id, sizeof(id), "WW-%05zu", *total);
        char desc[ZP_DESC_MAX];
        snprintf(desc, sizeof(desc),
                 "World-writable file in sensitive location (mode %04o)",
                 st.st_mode & 0777);
        char rem[ZP_REMEDIATION_MAX];
        snprintf(rem, sizeof(rem),
                 "chmod o-w <PATH>");
        zp_evidence_add(c, id, child, desc, rem, weight,
                          ZP_VERDICT_DETERMINISTIC, sev);
    }
    zp_dir_close(d);
    return ZP_OK;
}

int zp_probe_world_writable(struct zp_evidence_chain *c,
                                const char *root, struct audit_ctx *ctx)
{
    (void)root;
    (void)ctx;
    if (c == NULL) {
        return ZP_ERR_INVAL;
    }
    size_t total = 0;
    for (size_t i = 0; i < sizeof(SENSITIVE_DIRS) / sizeof(SENSITIVE_DIRS[0]);
         i++) {
        scan_dir(SENSITIVE_DIRS[i], 0, c, &total);
    }
    for (size_t i = 0; i < sizeof(STICKY_DIRS) / sizeof(STICKY_DIRS[0]);
         i++) {
        struct stat st;
        if (lstat(STICKY_DIRS[i], &st) != 0) continue;
        if (!S_ISDIR(st.st_mode)) continue;
        if (!(st.st_mode & S_ISVTX)) {
            char id[ZP_EVIDENCE_ID_MAX];
            snprintf(id, sizeof(id), "STICKY-%03zu", i + 1);
            char desc[ZP_DESC_MAX];
            snprintf(desc, sizeof(desc),
                     "Sensitive directory %s lacks sticky bit "
                     "(mode %04o)", STICKY_DIRS[i], st.st_mode & 0777);
            char rem[ZP_REMEDIATION_MAX];
            snprintf(rem, sizeof(rem),
                     "chmod +t %s", STICKY_DIRS[i]);
            zp_evidence_add(c, id, STICKY_DIRS[i], desc, rem, 0.85f,
                              ZP_VERDICT_DETERMINISTIC, ZP_SEV_HIGH);
        }
    }
    return ZP_OK;
}
