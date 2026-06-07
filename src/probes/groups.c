/*
 * groups.c - Privileged group membership detector
 *
 * Checks whether the current user is a member of any group that
 * grants direct or indirect privilege escalation:
 *   - docker     (full host root via docker run)
 *   - lxd        (full host root via lxc)
 *   - disk       (raw block device read/write)
 *   - shadow     (read /etc/shadow)
 *   - root       (uid 0)
 *   - adm        (read /var/log)
 *   - sudo/wheel (sudo)
 *   - kmem       (read kernel memory)
 *   - mem        (read /dev/mem)
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
#include <unistd.h>
#include <grp.h>
#include <pwd.h>

struct priv_group {
    const char *name;
    enum zp_severity sev;
    float       weight;
    const char *description;
};

static const struct priv_group PRIV_GROUPS[] = {
    {"docker", ZP_SEV_CRITICAL, 0.95f,
     "Member of docker group -> root via 'docker run -v /:/host'"},
    {"lxd",    ZP_SEV_CRITICAL, 0.95f,
     "Member of lxd group -> root via 'lxc launch privileged'"},
    {"disk",   ZP_SEV_CRITICAL, 0.9f,
     "Member of disk group -> raw read/write to block devices"},
    {"kmem",   ZP_SEV_HIGH,     0.9f,
     "Member of kmem group -> read kernel memory"},
    {"mem",    ZP_SEV_HIGH,     0.9f,
     "Member of mem group -> read /dev/mem"},
    {"shadow", ZP_SEV_HIGH,     0.8f,
     "Member of shadow group -> read /etc/shadow"},
    {"root",   ZP_SEV_CRITICAL, 0.99f,
     "Member of root group (uid 0)"},
    {"sudo",   ZP_SEV_HIGH,     0.85f,
     "Member of sudo group"},
    {"wheel",  ZP_SEV_HIGH,     0.85f,
     "Member of wheel group"},
    {"adm",    ZP_SEV_MEDIUM,   0.5f,
     "Member of adm group -> read /var/log"},
    {"video",  ZP_SEV_LOW,      0.3f,
     "Member of video group -> framebuffer access"},
    {"netdev", ZP_SEV_LOW,      0.3f,
     "Member of netdev group -> manage network interfaces"},
    {"input",  ZP_SEV_LOW,      0.3f,
     "Member of input group -> capture input devices"},
    {"ssl-cert", ZP_SEV_LOW,    0.2f,
     "Member of ssl-cert group -> read private keys"},
};

int zp_probe_groups(struct zp_evidence_chain *c, const char *root,
                       struct audit_ctx *ctx)
{
    (void)root;
    (void)ctx;
    if (c == NULL) {
        return ZP_ERR_INVAL;
    }
    uid_t uid = getuid();
    struct passwd *pw = getpwuid(uid);
    if (pw == NULL) {
        return ZP_ERR_IO;
    }
    size_t total = 0;
    size_t n_priv = sizeof(PRIV_GROUPS) / sizeof(PRIV_GROUPS[0]);
    for (size_t i = 0; i < n_priv; i++) {
        const struct priv_group *pg = &PRIV_GROUPS[i];
        struct group *g = getgrnam(pg->name);
        if (g == NULL) continue;
        bool member = false;
        if (g->gr_gid == pw->pw_gid) {
            member = true;
        } else {
            for (char **m = g->gr_mem; m != NULL && *m != NULL; m++) {
                if (strcmp(*m, pw->pw_name) == 0) {
                    member = true;
                    break;
                }
            }
        }
        if (!member) continue;
        total++;
        char id[ZP_EVIDENCE_ID_MAX];
        snprintf(id, sizeof(id), "GRP-%s", pg->name);
        char desc[ZP_DESC_MAX];
        snprintf(desc, sizeof(desc), "%s (gid=%u)", pg->description, g->gr_gid);
        char rem[ZP_REMEDIATION_MAX];
        snprintf(rem, sizeof(rem),
                 "Remove user from '%s' group unless required", pg->name);
        zp_evidence_add(c, id, pw->pw_name, desc, rem,
                          pg->weight, ZP_VERDICT_DETERMINISTIC,
                          pg->sev);
    }
    if (total == 0) {
        zp_evidence_add(c, "GRP-CLEAN", pw->pw_name,
                           "User is not a member of any privileged group",
                           "No action required",
                           0.1f, ZP_VERDICT_REJECT, ZP_SEV_INFO);
    }
    return ZP_OK;
}

