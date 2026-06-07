/*
 * suid.c - SUID / SGID binary scanner
 *
 * Walks the filesystem (or a configurable root) looking for executables
 * with the SUID or SGID bit set.  Each finding is added to the
 * evidence chain; root-owned SUIDs and known-dangerous binaries
 * (nmap, vim, find, less, ...) are weighted higher.
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
#include <errno.h>

#define SUID_MAX_DEPTH        8
#define SUID_MAX_FINDINGS     4096
#define SUID_DANGEROUS_COUNT  (sizeof(DANGEROUS) / sizeof(DANGEROUS[0]))

static const char *DANGEROUS[] = {
    "nmap", "vim", "vi", "nano", "find", "less", "more", "awk", "gawk",
    "perl", "python", "python2", "python3", "ruby", "bash", "sh", "dash",
    "env", "strace", "ltrace", "cp", "mv", "chown", "chmod", "tee", "socat",
    "php",
    "node",
    "gdb",
    "busybox"
};

static bool is_dangerous_basename(const char *path)
{
    const char *base = strrchr(path, '/');
    base = base ? base + 1 : path;
    for (size_t i = 0; i < SUID_DANGEROUS_COUNT; i++) {
        if (strcmp(base, DANGEROUS[i]) == 0) {
            return true;
        }
    }
    size_t bl = strlen(base);
    for (size_t i = 0; i < SUID_DANGEROUS_COUNT; i++) {
        size_t dl = strlen(DANGEROUS[i]);
        if (bl > dl && strcmp(base + bl - dl, DANGEROUS[i]) == 0) {
            char prev = base[bl - dl - 1];
            if (prev == '-' || prev == '.') {
                return true;
            }
        }
    }
    return false;
}

static bool in_skip_dir(const char *name)
{
    static const char *SKIP[] = {
        "proc", "sys", "dev", "snap", "run", "lost+found"
    };
    for (size_t i = 0; i < sizeof(SKIP) / sizeof(SKIP[0]); i++) {
        if (strcmp(name, SKIP[i]) == 0) {
            return true;
        }
    }
    return false;
}

static int scan_dir(const char *path, int depth, struct zp_evidence_chain *c,
                    size_t *total)
{
    DIR *d = NULL;
    if (zp_dir_open(&d, path) != ZP_OK) {
        return ZP_OK;
    }
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) {
            continue;
        }
        if (*total >= SUID_MAX_FINDINGS) {
            break;
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
        if (S_ISLNK(st.st_mode)) {
            continue;
        }
        if (S_ISDIR(st.st_mode)) {
            if (in_skip_dir(de->d_name)) {
                continue;
            }
            if (depth + 1 < SUID_MAX_DEPTH) {
                scan_dir(child, depth + 1, c, total);
            }
            continue;
        }
        if (!S_ISREG(st.st_mode)) {
            continue;
        }
        if ((st.st_mode & (S_ISUID | S_ISGID)) == 0) {
            continue;
        }
        if (!(st.st_mode & S_IXUSR) && !(st.st_mode & S_IXGRP) &&
            !(st.st_mode & S_IXOTH)) {
            continue;
        }
        (*total)++;
        bool root_owned = (st.st_uid == 0);
        bool dangerous  = is_dangerous_basename(child);
        float weight;
        enum zp_severity sev;
        if (dangerous && root_owned) {
            weight = 0.95f;
            sev    = ZP_SEV_CRITICAL;
        } else if (dangerous) {
            weight = 0.85f;
            sev    = ZP_SEV_HIGH;
        } else if (root_owned) {
            weight = 0.5f;
            sev    = ZP_SEV_MEDIUM;
        } else {
            weight = 0.3f;
            sev    = ZP_SEV_LOW;
        }
        char id[ZP_EVIDENCE_ID_MAX];
        snprintf(id, sizeof(id), "SUID-%05zu", *total);
        char desc[ZP_DESC_MAX];
        snprintf(desc, sizeof(desc),
                 "%s SUID binary %s by uid=%lu (%s%s)",
                 root_owned ? "Root-owned" : "Non-root",
                 (st.st_mode & S_ISUID) ? "SUID" : "SGID",
                 (unsigned long)st.st_uid,
                 dangerous ? "dangerous basename" : "standard binary",
                 "");
        char rem[ZP_REMEDIATION_MAX];
        snprintf(rem, sizeof(rem),
                 "Remove the SUID bit: chmod u-s <PATH>");
        zp_evidence_add(c, id, child, desc, rem, weight,
                          ZP_VERDICT_DETERMINISTIC, sev);
    }
    zp_dir_close(d);
    return ZP_OK;
}

int zp_probe_suid(struct zp_evidence_chain *c, const char *root,
                    struct audit_ctx *ctx)
{
    (void)ctx;
    if (c == NULL || root == NULL) {
        return ZP_ERR_INVAL;
    }
    size_t total = 0;
    return scan_dir(root, 0, c, &total);
}
