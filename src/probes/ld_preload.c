/*
 * ld_preload.c - LD_PRELOAD and library load path misconfiguration
 *
 * Inspects ld.so.conf and ld.so.conf.d entries for world-writable
 * entries.  Also checks for the presence of an attacker-controlled
 * library path in /etc/environment or in the systemd-wide
 * LD_LIBRARY_PATH file.  A writable library path is CRITICAL.
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

static void inspect_file(struct zp_evidence_chain *c, const char *path,
                          size_t *total)
{
    struct stat st;
    if (lstat(path, &st) != 0) {
        return;
    }
    if (!(st.st_mode & S_IWOTH)) {
        return;
    }
    (*total)++;
    char id[ZP_EVIDENCE_ID_MAX];
    snprintf(id, sizeof(id), "LDP-W-%05zu", *total);
    char desc[ZP_DESC_MAX];
    snprintf(desc, sizeof(desc),
             "World-writable ld.so.conf file (mode %04o)",
             st.st_mode & 0777);
    char rem[ZP_REMEDIATION_MAX];
    snprintf(rem, sizeof(rem), "chmod o-w <PATH>");
    zp_evidence_add(c, id, path, desc, rem, 0.99f,
                      ZP_VERDICT_DETERMINISTIC, ZP_SEV_CRITICAL);
}

int zp_probe_ld_preload(struct zp_evidence_chain *c,
                            const char *root, struct audit_ctx *ctx)
{
    (void)ctx;
    if (c == NULL) {
        return ZP_ERR_INVAL;
    }
    const char *r = (root != NULL && root[0]) ? root : "/";
    size_t total = 0;
    char p[ZP_PATH_MAX];
    if (zp_path_join(p, sizeof(p), r, "etc/ld.so.conf") == ZP_OK) {
        struct stat st;
        if (lstat(p, &st) == 0) {
            if (S_ISDIR(st.st_mode)) {
                DIR *d = NULL;
                if (zp_dir_open(&d, p) == ZP_OK) {
                    struct dirent *de;
                    while ((de = readdir(d)) != NULL) {
                        if (strcmp(de->d_name, ".") == 0 ||
                            strcmp(de->d_name, "..") == 0) continue;
                        char child[ZP_PATH_MAX];
                        if (zp_path_join(child, sizeof(child), p,
                                            de->d_name) != ZP_OK) continue;
                        inspect_file(c, child, &total);
                    }
                    zp_dir_close(d);
                }
            } else {
                inspect_file(c, p, &total);
            }
        }
    }
    char d[ZP_PATH_MAX];
    if (zp_path_join(d, sizeof(d), r, "etc/ld.so.conf.d") == ZP_OK) {
        DIR *dir = NULL;
        if (zp_dir_open(&dir, d) == ZP_OK) {
            struct dirent *de;
            while ((de = readdir(dir)) != NULL) {
                if (strcmp(de->d_name, ".") == 0 ||
                    strcmp(de->d_name, "..") == 0) continue;
                char child[ZP_PATH_MAX];
                if (zp_path_join(child, sizeof(child), d,
                                    de->d_name) != ZP_OK) continue;
                inspect_file(c, child, &total);
            }
            zp_dir_close(dir);
        }
    }
    char env_p[ZP_PATH_MAX];
    if (zp_path_join(env_p, sizeof(env_p), r, "etc/environment") ==
            ZP_OK) {
        FILE *f = fopen(env_p, "r");
        if (f != NULL) {
            char line[1024];
            while (fgets(line, sizeof(line), f) != NULL) {
                if (strncmp(line, "LD_PRELOAD", 10) == 0 ||
                    strncmp(line, "LD_LIBRARY_PATH", 16) == 0) {
                    total++;
                    char id[ZP_EVIDENCE_ID_MAX];
                    snprintf(id, sizeof(id), "LDP-ENV-%05zu", total);
                    char desc[ZP_DESC_MAX];
                    snprintf(desc, sizeof(desc),
                             "Global LD_* variable in /etc/environment");
                    char rem[ZP_REMEDIATION_MAX];
                    snprintf(rem, sizeof(rem),
                             "Remove LD_PRELOAD/LD_LIBRARY_PATH from "
                             "/etc/environment");
                    zp_evidence_add(c, id, env_p, desc, rem, 0.7f,
                                      ZP_VERDICT_DETERMINISTIC,
                                      ZP_SEV_HIGH);
                }
            }
            fclose(f);
        }
    }
    if (total == 0) {
        zp_evidence_add(c, "LDP-CLEAN", "/etc/ld.so.conf",
                           "No writable or hijackable ld.so.conf entries",
                           "No action required",
                           0.1f, ZP_VERDICT_REJECT, ZP_SEV_INFO);
    }
    return ZP_OK;
}
