/*
 * process.c - Root-owned process misconfiguration detector
 *
 * Scans /proc for processes whose executable file is world-writable
 * or has the SUID bit set from an unusual location, or that are
 * running with a deleted binary.  Each finding is added to the chain.
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

#define PROC_MAX_SCAN 4096

static int read_link_int(const char *path, const char *link,
                          char *out, size_t cap)
{
    char p[ZP_PATH_MAX];
    if (zp_path_join(p, sizeof(p), path, link) != ZP_OK) {
        return -1;
    }
    ssize_t n = readlink(p, out, cap - 1);
    if (n < 0) {
        return -1;
    }
    out[n] = '\0';
    return 0;
}

static int read_status_field(const char *path, const char *field,
                              char *out, size_t cap)
{
    char p[ZP_PATH_MAX];
    if (zp_path_join(p, sizeof(p), path, "status") != ZP_OK) {
        return -1;
    }
    FILE *f = fopen(p, "r");
    if (f == NULL) {
        return -1;
    }
    char line[512];
    size_t flen = strlen(field);
    int    rc   = -1;
    while (fgets(line, sizeof(line), f) != NULL) {
        if (strncmp(line, field, flen) == 0 && line[flen] == ':') {
            const char *v = line + flen + 1;
            while (*v == ' ' || *v == '\t') v++;
            size_t l = strlen(v);
            while (l > 0 && (v[l - 1] == '\n' || v[l - 1] == '\r')) l--;
            if (l >= cap) l = cap - 1;
            memcpy(out, v, l);
            out[l] = '\0';
            rc = 0;
            break;
        }
    }
    fclose(f);
    return rc;
}

int zp_probe_process(struct zp_evidence_chain *c, const char *root,
                        struct audit_ctx *ctx)
{
    (void)ctx;
    if (c == NULL) {
        return ZP_ERR_INVAL;
    }
    const char *r = (root != NULL && root[0]) ? root : "/";
    char proc[ZP_PATH_MAX];
    if (zp_path_join(proc, sizeof(proc), r, "proc") != ZP_OK) {
        return ZP_OK;
    }
    DIR *d = NULL;
    if (zp_dir_open(&d, proc) != ZP_OK) {
        return ZP_OK;
    }
    struct dirent *de;
    size_t total = 0;
    while ((de = readdir(d)) != NULL) {
        if (total >= PROC_MAX_SCAN) break;
        if (de->d_name[0] < '0' || de->d_name[0] > '9') continue;
        char pdir[ZP_PATH_MAX];
        if (zp_path_join(pdir, sizeof(pdir), proc, de->d_name) !=
                ZP_OK) continue;
        char uid_str[32];
        if (read_status_field(pdir, "Uid", uid_str,
                              sizeof(uid_str)) != 0) continue;
        long real_uid = -1;
        const char *u = uid_str;
        while (*u == ' ' || *u == '\t') u++;
        real_uid = strtol(u, NULL, 10);
        if (real_uid != 0) continue;
        char exe[ZP_PATH_MAX];
        if (read_link_int(pdir, "exe", exe, sizeof(exe)) != 0) continue;
        if (strstr(exe, " (deleted)") != NULL) {
            total++;
            char id[ZP_EVIDENCE_ID_MAX];
            snprintf(id, sizeof(id), "PROC-DEL-%05zu", total);
            char desc[ZP_DESC_MAX];
            snprintf(desc, sizeof(desc),
                     "Root process running deleted binary");
            char rem[ZP_REMEDIATION_MAX];
            snprintf(rem, sizeof(rem),
                     "Restart the service to refresh binary");
            zp_evidence_add(c, id, exe, desc, rem, 0.7f,
                              ZP_VERDICT_DETERMINISTIC, ZP_SEV_MEDIUM);
        }
        struct stat st;
        if (stat(exe, &st) == 0 && (st.st_mode & S_IWOTH)) {
            total++;
            char id[ZP_EVIDENCE_ID_MAX];
            snprintf(id, sizeof(id), "PROC-WW-%05zu", total);
            char desc[ZP_DESC_MAX];
            snprintf(desc, sizeof(desc),
                     "Root process running world-writable executable");
            char rem[ZP_REMEDIATION_MAX];
            snprintf(rem, sizeof(rem), "chmod o-w <PATH>");
            zp_evidence_add(c, id, exe, desc, rem, 0.95f,
                              ZP_VERDICT_DETERMINISTIC,
                              ZP_SEV_CRITICAL);
        }
    }
    zp_dir_close(d);
    if (total == 0) {
        zp_evidence_add(c, "PROC-CLEAN", "/proc",
                           "No root processes with deleted/ww binaries",
                           "No action required",
                           0.1f, ZP_VERDICT_REJECT, ZP_SEV_INFO);
    }
    return ZP_OK;
}
