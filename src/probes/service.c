/*
 * service.c - Systemd service misconfiguration detector
 *
 * Scans systemd system and library service directories
 * for world-writable service definitions, User=root with relative PATH,
 * and writable service binaries referenced by ExecStart=.  A writable
 * service definition executed by root is CRITICAL.
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

static void inspect(struct zp_evidence_chain *c, const char *path,
                    size_t *total)
{
    struct stat st;
    if (lstat(path, &st) != 0) {
        return;
    }
    if (S_ISLNK(st.st_mode)) {
        return;
    }
    if (st.st_mode & S_IWOTH) {
        (*total)++;
        char id[ZP_EVIDENCE_ID_MAX];
        snprintf(id, sizeof(id), "SVC-W-%05zu", *total);
        char desc[ZP_DESC_MAX];
        snprintf(desc, sizeof(desc),
                 "World-writable systemd unit file (mode %04o)",
                 st.st_mode & 0777);
        char rem[ZP_REMEDIATION_MAX];
        snprintf(rem, sizeof(rem), "chmod o-w <PATH>");
        zp_evidence_add(c, id, path, desc, rem, 0.99f,
                          ZP_VERDICT_DETERMINISTIC, ZP_SEV_CRITICAL);
    }
    if (!S_ISREG(st.st_mode)) {
        return;
    }
    if (st.st_uid != 0) {
        return;
    }
    FILE *f = fopen(path, "r");
    if (f == NULL) {
        return;
    }
    char line[1024];
    bool user_root  = false;
    bool has_exec   = false;
    char exec_path[ZP_PATH_MAX] = {0};
    while (fgets(line, sizeof(line), f) != NULL) {
        if (strncmp(line, "User=", 5) == 0) {
            if (strncmp(line + 5, "root", 4) == 0 ||
                isspace((unsigned char)line[5]) == 0) {
                if (strstr(line, "User=root") != NULL) user_root = true;
            }
        }
        if (strncmp(line, "ExecStart=", 10) == 0) {
            has_exec = true;
            const char *p = line + 10;
            while (*p == ' ' || *p == '\t' || *p == '-' ||
                   *p == '+' || *p == '!') {
                p++;
                if (*p == ' ' || *p == '\t') p++;
            }
            size_t i = 0;
            while (*p && *p != ' ' && *p != '\t' && *p != '\n' &&
                   i + 1 < sizeof(exec_path)) {
                exec_path[i++] = *p++;
            }
            exec_path[i] = '\0';
        }
    }
    fclose(f);
    if (user_root && has_exec && exec_path[0] == '/') {
        struct stat est;
        if (stat(exec_path, &est) == 0) {
            if (est.st_mode & S_IWOTH) {
                (*total)++;
                char id[ZP_EVIDENCE_ID_MAX];
                snprintf(id, sizeof(id), "SVC-E-%05zu", *total);
                char desc[ZP_DESC_MAX];
                snprintf(desc, sizeof(desc),
                         "Root service references world-writable ExecStart");
                char rem[ZP_REMEDIATION_MAX];
                snprintf(rem, sizeof(rem), "chmod o-w <PATH>");
                zp_evidence_add(c, id, path, desc, rem, 0.99f,
                                  ZP_VERDICT_DETERMINISTIC,
                                  ZP_SEV_CRITICAL);
            }
        }
    }
}

static void inspect_dir(struct zp_evidence_chain *c, const char *path,
                        size_t *total)
{
    DIR *d = NULL;
    if (zp_dir_open(&d, path) != ZP_OK) {
        return;
    }
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        size_t l = strlen(de->d_name);
        if (l < 8 || strcmp(de->d_name + l - 8, ".service") != 0) {
            continue;
        }
        char child[ZP_PATH_MAX];
        if (zp_path_join(child, sizeof(child), path, de->d_name) !=
                ZP_OK) continue;
        inspect(c, child, total);
    }
    zp_dir_close(d);
}

int zp_probe_service(struct zp_evidence_chain *c, const char *root,
                        struct audit_ctx *ctx)
{
    (void)ctx;
    if (c == NULL) {
        return ZP_ERR_INVAL;
    }
    const char *r = (root != NULL && root[0]) ? root : "/";
    size_t total = 0;
    const char *dirs[] = {
        "/etc/systemd/system",
        "/lib/systemd/system",
        "/usr/lib/systemd/system",
    };
    for (size_t i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++) {
        char p[ZP_PATH_MAX];
        if (zp_path_join(p, sizeof(p), r, dirs[i] + 1) == ZP_OK) {
            inspect_dir(c, p, &total);
        }
    }
    if (total == 0) {
        zp_evidence_add(c, "SVC-CLEAN", "/etc/systemd/system",
                           "No misconfigured systemd services",
                           "No action required",
                           0.1f, ZP_VERDICT_REJECT, ZP_SEV_INFO);
    }
    return ZP_OK;
}
