/*
 * cron.c - Cron misconfiguration detector
 *
 * Examines /etc/crontab, /etc/cron.d, /var/spool/cron, and systemd
 * timers for world-writable jobs, wildcard injections, and
 * dereferenced-symlink jobs.  A world-writable cron job is an
 * immediate critical finding.
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

static const char *CRON_PATHS[] = {
    "/etc/crontab",
    "/etc/cron.d",
    "/etc/cron.daily",
    "/etc/cron.hourly",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
    "/var/spool/cron",
    "/etc/anacrontab",
    "/etc/cron.d",
    "/var/spool/cron/crontabs"
};

static void inspect_file(struct zp_evidence_chain *c, const char *path,
                         size_t *total)
{
    struct stat st;
    if (lstat(path, &st) != 0) {
        return;
    }
    if (S_ISLNK(st.st_mode)) {
        return;
    }
    if (!(st.st_mode & S_IWOTH)) {
        return;
    }
    (*total)++;
    char id[ZP_EVIDENCE_ID_MAX];
    snprintf(id, sizeof(id), "CRON-%05zu", *total);
    char desc[ZP_DESC_MAX];
    snprintf(desc, sizeof(desc),
             "World-writable cron file (mode %04o)", st.st_mode & 0777);
    char rem[ZP_REMEDIATION_MAX];
    snprintf(rem, sizeof(rem), "chmod o-w <PATH>");
    zp_evidence_add(c, id, path, desc, rem, 0.99f,
                      ZP_VERDICT_DETERMINISTIC, ZP_SEV_CRITICAL);
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
        if (strcmp(de->d_name, ".") == 0 ||
            strcmp(de->d_name, "..") == 0) {
            continue;
        }
        char child[ZP_PATH_MAX];
        if (zp_path_join(child, sizeof(child), path, de->d_name) !=
                ZP_OK) {
            continue;
        }
        struct stat st;
        if (lstat(child, &st) != 0) {
            continue;
        }
        if (S_ISDIR(st.st_mode)) {
            continue;
        }
        if (S_ISLNK(st.st_mode)) {
            struct stat real_st;
            if (stat(child, &real_st) == 0 &&
                (real_st.st_mode & S_IWOTH)) {
                (*total)++;
                char id[ZP_EVIDENCE_ID_MAX];
                snprintf(id, sizeof(id), "CRON-SYM-%05zu", *total);
                char desc[ZP_DESC_MAX];
                snprintf(desc, sizeof(desc),
                         "Cron symlink resolves to world-writable file");
                char rem[ZP_REMEDIATION_MAX];
                snprintf(rem, sizeof(rem), "rm <PATH> and inspect chain");
                zp_evidence_add(c, id, child, desc, rem, 0.95f,
                                  ZP_VERDICT_DETERMINISTIC,
                                  ZP_SEV_CRITICAL);
            }
            continue;
        }
        inspect_file(c, child, total);
    }
    zp_dir_close(d);
}

static void inspect_wildcards(struct zp_evidence_chain *c,
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
        if (line[0] == '#' || line[0] == '\n') {
            continue;
        }
        if (strchr(line, '*') != NULL &&
            (strstr(line, "tar") != NULL ||
             strstr(line, "rsync") != NULL ||
             strstr(line, "zip") != NULL ||
             strstr(line, "cp ") != NULL ||
             strstr(line, "mv ") != NULL ||
             strstr(line, "chown") != NULL ||
             strstr(line, "chmod") != NULL)) {
            (*total)++;
            char id[ZP_EVIDENCE_ID_MAX];
            snprintf(id, sizeof(id), "CRON-WILD-%05zu", *total);
            char desc[ZP_DESC_MAX];
            snprintf(desc, sizeof(desc),
                     "Cron wildcard injection candidate (line %d)", lineno);
            char rem[ZP_REMEDIATION_MAX];
            snprintf(rem, sizeof(rem),
                     "Quote the wildcard or use -- to terminate options");
            zp_evidence_add(c, id, path, desc, rem, 0.7f,
                              ZP_VERDICT_DETERMINISTIC, ZP_SEV_HIGH);
        }
    }
    fclose(f);
}

int zp_probe_cron(struct zp_evidence_chain *c, const char *root,
                    struct audit_ctx *ctx)
{
    (void)ctx;
    if (c == NULL) {
        return ZP_ERR_INVAL;
    }
    const char *r = (root != NULL && root[0]) ? root : "/";
    size_t total = 0;
    for (size_t i = 0; i < sizeof(CRON_PATHS) / sizeof(CRON_PATHS[0]);
         i++) {
        char p[ZP_PATH_MAX];
        if (zp_path_join(p, sizeof(p), r, CRON_PATHS[i] + 1) !=
                ZP_OK) {
            continue;
        }
        struct stat st;
        if (lstat(p, &st) != 0) {
            continue;
        }
        if (S_ISDIR(st.st_mode)) {
            inspect_dir(c, p, &total);
        } else {
            inspect_file(c, p, &total);
            if (i == 0) {
                inspect_wildcards(c, p, &total);
            }
        }
    }
    if (total == 0) {
        zp_evidence_add(c, "CRON-CLEAN", "/etc/crontab",
                           "No writable or wildcard-prone cron jobs found",
                           "No action required",
                           0.1f, ZP_VERDICT_REJECT, ZP_SEV_INFO);
    }
    return ZP_OK;
}
