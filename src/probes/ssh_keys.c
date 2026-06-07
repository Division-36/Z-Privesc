/*
 * ssh_keys.c - World-readable SSH private key detector
 *
 * Scans user SSH directories for private key files
 * with overly permissive modes.  A world-readable RSA / Ed25519 /
 * ECDSA private key is a HIGH severity finding.
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

static const char *KEY_NAMES[] = {
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    "id_xmss", "identity", "key", "private_key", NULL
};

static bool is_key_file(const char *name)
{
    for (size_t i = 0; KEY_NAMES[i] != NULL; i++) {
        if (strcmp(name, KEY_NAMES[i]) == 0) {
            return true;
        }
    }
    if (strstr(name, "_key") != NULL || strstr(name, ".pem") != NULL) {
        return true;
    }
    return false;
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
            strcmp(de->d_name, "..") == 0) continue;
        if (!is_key_file(de->d_name)) continue;
        char child[ZP_PATH_MAX];
        if (zp_path_join(child, sizeof(child), path, de->d_name) !=
                ZP_OK) continue;
        struct stat st;
        if (lstat(child, &st) != 0) continue;
        if (!S_ISREG(st.st_mode)) continue;
        if (!(st.st_mode & S_IWOTH) && (st.st_mode & S_IRGRP) == 0 &&
            (st.st_mode & S_IROTH) == 0) {
            continue;
        }
        (*total)++;
        char id[ZP_EVIDENCE_ID_MAX];
        snprintf(id, sizeof(id), "SSH-%05zu", *total);
        char desc[ZP_DESC_MAX];
        snprintf(desc, sizeof(desc),
                 "SSH private key with permissive mode (mode %04o)",
                 st.st_mode & 0777);
        char rem[ZP_REMEDIATION_MAX];
        snprintf(rem, sizeof(rem), "chmod 600 <PATH>");
        float weight = (st.st_mode & S_IWOTH) ? 0.95f : 0.6f;
        enum zp_severity sev = (st.st_mode & S_IWOTH)
                                  ? ZP_SEV_CRITICAL : ZP_SEV_HIGH;
        zp_evidence_add(c, id, child, desc, rem, weight,
                          ZP_VERDICT_DETERMINISTIC, sev);
    }
    zp_dir_close(d);
}

int zp_probe_ssh_keys(struct zp_evidence_chain *c, const char *root,
                          struct audit_ctx *ctx)
{
    (void)ctx;
    if (c == NULL) {
        return ZP_ERR_INVAL;
    }
    const char *r = (root != NULL && root[0]) ? root : "/";
    size_t total = 0;
    char p[ZP_PATH_MAX];
    if (zp_path_join(p, sizeof(p), r, "root/.ssh") == ZP_OK) {
        inspect_dir(c, p, &total);
    }
    if (zp_path_join(p, sizeof(p), r, "home") == ZP_OK) {
        DIR *d = NULL;
        if (zp_dir_open(&d, p) == ZP_OK) {
            struct dirent *de;
            while ((de = readdir(d)) != NULL) {
                if (strcmp(de->d_name, ".") == 0 ||
                    strcmp(de->d_name, "..") == 0) continue;
                char sshd[ZP_PATH_MAX];
                if (zp_path_join(sshd, sizeof(sshd), p,
                                    de->d_name) != ZP_OK) continue;
                if (zp_path_join(sshd, sizeof(sshd), sshd,
                                    ".ssh") != ZP_OK) continue;
                inspect_dir(c, sshd, &total);
            }
            zp_dir_close(d);
        }
    }
    if (total == 0) {
        zp_evidence_add(c, "SSH-CLEAN", "~/.ssh",
                           "No permissive SSH private keys found",
                           "No action required",
                           0.1f, ZP_VERDICT_REJECT, ZP_SEV_INFO);
    }
    return ZP_OK;
}
