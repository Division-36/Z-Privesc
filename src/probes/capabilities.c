/*
 * capabilities.c - Linux capabilities auditor
 *
 * Scans the filesystem for binaries with extended-attribute capabilities
 * (getcap -r) and inspects /proc/self/status for granted capabilities.
 * Critical capabilities (CAP_SYS_ADMIN, CAP_DAC_OVERRIDE, CAP_SETUID,
 * CAP_SETGID, CAP_SYS_PTRACE, CAP_NET_RAW) escalate the finding.
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
#include <sys/xattr.h>
#include <unistd.h>

#define CAP_SCAN_MAX_DEPTH     8
#define CAP_SCAN_MAX_FINDINGS  2048
#define CAP_FILE_MAX           65536

static const char *CRITICAL_CAPS[] = {
    "cap_sys_admin",   "cap_dac_override", "cap_setuid",     "cap_setgid",
    "cap_sys_ptrace",  "cap_net_raw",      "cap_dac_read_search",
    "cap_sys_module",  "cap_sys_rawio",    "cap_linux_immutable",
    "cap_sys_boot",
    "cap_net_admin"
};
#define CRITICAL_CAPS_COUNT (sizeof(CRITICAL_CAPS) / sizeof(CRITICAL_CAPS[0]))

static bool has_critical_cap(const char *caps)
{
    if (caps == NULL) {
        return false;
    }
    for (size_t i = 0; i < CRITICAL_CAPS_COUNT; i++) {
        if (strcasestr(caps, CRITICAL_CAPS[i]) != NULL) {
            return true;
        }
    }
    return false;
}

static int read_cap_xattr(const char *path, char *out, size_t cap)
{
    ssize_t n = getxattr(path, "security.capability", out, cap - 1);
    if (n < 0) {
        return -1;
    }
    out[n]   = '\0';
    out[cap - 1] = '\0';
    return 0;
}

static void format_cap_text(const unsigned char *raw, size_t n, char *out,
                            size_t out_cap)
{
    size_t o = 0;
    for (size_t i = 0; i < n && o + 2 < out_cap; i++) {
        o += (size_t)snprintf(out + o, out_cap - o, "%02x", raw[i]);
    }
}

static int scan_dir_caps(const char *path, int depth,
                         struct zp_evidence_chain *c, size_t *total)
{
    DIR *d = NULL;
    if (zp_dir_open(&d, path) != ZP_OK) {
        return ZP_OK;
    }
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (*total >= CAP_SCAN_MAX_FINDINGS) {
            break;
        }
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) {
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
        if (S_ISLNK(st.st_mode)) {
            continue;
        }
        if (S_ISDIR(st.st_mode)) {
            if (depth + 1 < CAP_SCAN_MAX_DEPTH) {
                scan_dir_caps(child, depth + 1, c, total);
            }
            continue;
        }
        if (!S_ISREG(st.st_mode)) {
            continue;
        }
        char raw[CAP_FILE_MAX];
        if (read_cap_xattr(child, raw, sizeof(raw)) != 0) {
            continue;
        }
        char hex[CAP_FILE_MAX * 2 + 4];
        format_cap_text((const unsigned char *)raw, strlen(raw), hex,
                        sizeof(hex));
        char text[512];
        snprintf(text, sizeof(text),
                 "%s+%s", "all", (raw[0] & 0x01) ? "ep" : "p");
        bool crit = has_critical_cap(text);
        float weight = crit ? 0.9f : 0.5f;
        enum zp_severity sev = crit ? ZP_SEV_HIGH
                                        : ZP_SEV_MEDIUM;
        (*total)++;
        char id[ZP_EVIDENCE_ID_MAX];
        snprintf(id, sizeof(id), "CAP-%05zu", *total);
        char desc[ZP_DESC_MAX];
        snprintf(desc, sizeof(desc),
                 "File capability set on <PATH>: <CAPSET>");
        char rem[ZP_REMEDIATION_MAX];
        snprintf(rem, sizeof(rem),
                 "Drop the capability: setcap -r <PATH>");
        zp_evidence_add(c, id, child, desc, rem, weight,
                          ZP_VERDICT_DETERMINISTIC, sev);
    }
    zp_dir_close(d);
    return ZP_OK;
}

int zp_probe_capabilities(struct zp_evidence_chain *c,
                             const char *root, struct audit_ctx *ctx)
{
    (void)ctx;
    if (c == NULL || root == NULL) {
        return ZP_ERR_INVAL;
    }
    size_t total = 0;
    scan_dir_caps(root, 0, c, &total);
    char line[1024];
    if (zp_read_proc_self_status_field("CapBnd", line,
                                          sizeof(line)) == ZP_OK) {
        if (has_critical_cap(line)) {
            zp_evidence_add(c, "CAP-PROC-BND",
                "/proc/self/status",
                "Process bounding set retains critical capabilities",
                "Drop unused capabilities before launching shell",
                0.6f, ZP_VERDICT_DETERMINISTIC, ZP_SEV_MEDIUM);
        }
    }
    return ZP_OK;
}
