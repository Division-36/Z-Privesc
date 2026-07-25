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
#define CAP_FILE_MAX 8192

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

static ssize_t read_cap_xattr(const char *path, char *out, size_t cap)
{
    if (cap == 0) return -1;
    ssize_t n = getxattr(path, "security.capability", out, cap - 1);
    if (n < 0) {
        return -1;
    }
    if ((size_t)n >= cap) {
        return -1;
    }
    out[n] = '\0';
    return n;
}

static void format_cap_text(const unsigned char *raw, size_t n, char *out,
                            size_t out_cap)
{
    size_t o = 0;
    for (size_t i = 0; i < n && o + 2 < out_cap; i++) {
        o += (size_t)snprintf(out + o, out_cap - o, "%02x", raw[i]);
    }
}

static const char *CAP_NAMES[] = {
    "cap_chown", "cap_dac_override", "cap_dac_read_search", "cap_fowner",
    "cap_fsetid", "cap_kill", "cap_setgid", "cap_setuid", "cap_setpcap",
    "cap_linux_immutable", "cap_net_bind_service", "cap_net_broadcast",
    "cap_net_admin", "cap_net_raw", "cap_ipc_lock", "cap_ipc_owner",
    "cap_sys_module", "cap_sys_rawio", "cap_sys_chroot", "cap_sys_ptrace",
    "cap_sys_pacct", "cap_sys_admin", "cap_sys_boot", "cap_sys_nice",
    "cap_sys_resource", "cap_sys_time", "cap_sys_tty_config", "cap_mknod",
    "cap_lease", "cap_audit_write", "cap_audit_control", "cap_setfcap",
    "cap_mac_override", "cap_mac_admin", "cap_syslog", "cap_wake_alarm",
    "cap_block_suspend", "cap_audit_read", "cap_perfmon", "cap_bpf",
    "cap_checkpoint_restore"
};
#define CAP_NAMES_COUNT (sizeof(CAP_NAMES) / sizeof(CAP_NAMES[0]))

static void decode_caps(const unsigned char *raw, size_t n, char *out,
                        size_t out_cap)
{
    out[0] = '\0';
    if (n < 4) {
        return;
    }
    uint32_t magic = (uint32_t)raw[0] | ((uint32_t)raw[1] << 8) |
                     ((uint32_t)raw[2] << 16) | ((uint32_t)raw[3] << 24);
    uint32_t revision = magic >> 16;
    uint64_t permitted = 0;
    if (revision == 0x0100 && n >= 12) {
        permitted = (uint32_t)raw[4] | ((uint32_t)raw[5] << 8) |
                    ((uint32_t)raw[6] << 16) | ((uint32_t)raw[7] << 24);
    } else if ((revision == 0x0200 || revision == 0x0300) && n >= 20) {
        uint32_t lo = (uint32_t)raw[4] | ((uint32_t)raw[5] << 8) |
                      ((uint32_t)raw[6] << 16) | ((uint32_t)raw[7] << 24);
        uint32_t hi = (uint32_t)raw[8] | ((uint32_t)raw[9] << 8) |
                      ((uint32_t)raw[10] << 16) | ((uint32_t)raw[11] << 24);
        permitted = (uint64_t)lo | ((uint64_t)hi << 32);
    } else {
        return;
    }
    size_t o = 0;
    bool first = true;
    for (int i = 0; i < (int)CAP_NAMES_COUNT && o + 1 < out_cap; i++) {
        if (permitted & ((uint64_t)1 << i)) {
            int written = snprintf(out + o, out_cap - o, "%s%s",
                                   first ? "" : ", ", CAP_NAMES[i]);
            if (written < 0) break;
            o += (size_t)written;
            first = false;
        }
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
        ssize_t rlen = read_cap_xattr(child, raw, sizeof(raw));
        if (rlen < 0) {
            continue;
        }
        char hex[CAP_FILE_MAX * 2 + 4];
        format_cap_text((const unsigned char *)raw, (size_t)rlen, hex,
                        sizeof(hex));
        char capnames[512];
        decode_caps((const unsigned char *)raw, (size_t)rlen, capnames,
                    sizeof(capnames));
        bool crit = has_critical_cap(capnames);
        float weight = crit ? 0.9f : 0.5f;
        enum zp_severity sev = crit ? ZP_SEV_HIGH : ZP_SEV_MEDIUM;
        (*total)++;
        char id[ZP_EVIDENCE_ID_MAX];
        snprintf(id, sizeof(id), "CAP-%05zu", *total);
        char desc[ZP_DESC_MAX];
        if (capnames[0] != '\0') {
            snprintf(desc, sizeof(desc), "File has capability: %s", capnames);
        } else {
            snprintf(desc, sizeof(desc), "File has unknown capabilities set");
        }
        char rem[ZP_REMEDIATION_MAX];
        const char *base = strrchr(child, '/');
        if (base == NULL) {
            base = child;
        } else {
            base++;
        }
        snprintf(rem, sizeof(rem),
                 "Drop capability: setcap -r %.200s", base);
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
