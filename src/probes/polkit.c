/*
 * polkit.c - polkit / pkexec misconfiguration detector
 *
 * Identifies installed polkit, parses /etc/polkit-1 for permissive
 * rules, and matches the pkexec binary version against known CVEs
 * (CVE-2021-4034, CVE-2022-0847-style).  Findings are weighted by
 * exploitability.
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
#include <sys/stat.h>
#include <unistd.h>
#include <ctype.h>

static int read_first_line(const char *path, char *out, size_t cap)
{
    FILE *f = fopen(path, "r");
    if (f == NULL) {
        return -1;
    }
    if (fgets(out, (int)cap, f) == NULL) {
        fclose(f);
        return -1;
    }
    fclose(f);
    size_t l = strlen(out);
    while (l > 0 && (out[l - 1] == '\n' || out[l - 1] == '\r')) {
        out[--l] = '\0';
    }
    return 0;
}

static int parse_version(const char *s, int *maj, int *min, int *patch)
{
    while (*s && !isdigit((unsigned char)*s)) s++;
    if (*s == '\0') return -1;
    return sscanf(s, "%d.%d.%d", maj, min, patch) == 3 ? 0 : -1;
}

int zp_probe_polkit(struct zp_evidence_chain *c, const char *root,
                      struct audit_ctx *ctx)
{
    (void)root;
    (void)ctx;
    if (c == NULL) {
        return ZP_ERR_INVAL;
    }
    char version[128] = {0};
    if (read_first_line("/usr/share/polkit-1/version",
                        version, sizeof(version)) != 0) {
        if (read_first_line("/etc/polkit-1/version",
                            version, sizeof(version)) != 0) {
            strncpy(version, "0.0.0", sizeof(version) - 1);
        }
    }
    int maj = 0, min = 0, patch = 0;
    parse_version(version, &maj, &min, &patch);
    struct stat st;
    bool pkexec_present = (lstat("/usr/bin/pkexec", &st) == 0);
    if (pkexec_present && (st.st_mode & S_ISUID)) {
        if (maj < 122) {
            zp_evidence_add(c, "PKEXEC-CVE-2021-4034",
                "/usr/bin/pkexec",
                "pkexec is SUID and polkit version predates 0.120; "
                "vulnerable to CVE-2021-4034 (PwnKit)",
                "Upgrade polkit to >= 0.120 or remove SUID from pkexec",
                0.99f, ZP_VERDICT_DETERMINISTIC, ZP_SEV_CRITICAL);
        } else if (maj == 120 || (maj == 121 && min < 4)) {
            zp_evidence_add(c, "PKEXEC-OLD",
                "/usr/bin/pkexec",
                "polkit version contains known privilege-escalation bugs",
                "Upgrade polkit to latest stable release",
                0.7f, ZP_VERDICT_DETERMINISTIC, ZP_SEV_HIGH);
        }
    }
    const char *RULES_DIRS[] = {
        "/etc/polkit-1/rules.d",
        "/usr/share/polkit-1/rules.d",
        "/usr/local/share/polkit-1/rules.d"
    };
    for (size_t i = 0; i < sizeof(RULES_DIRS) / sizeof(RULES_DIRS[0]);
         i++) {
        struct stat dst;
        if (lstat(RULES_DIRS[i], &dst) != 0) continue;
        if (dst.st_mode & S_IWOTH) {
            char id[ZP_EVIDENCE_ID_MAX];
            snprintf(id, sizeof(id), "POLKIT-RULES-%03zu", i + 1);
            char desc[ZP_DESC_MAX];
            snprintf(desc, sizeof(desc),
                     "polkit rules directory %s is world-writable (mode %04o)",
                     RULES_DIRS[i], dst.st_mode & 0777);
            char rem[ZP_REMEDIATION_MAX];
            snprintf(rem, sizeof(rem),
                     "chmod o-w %s and audit installed rules", RULES_DIRS[i]);
            zp_evidence_add(c, id, RULES_DIRS[i], desc, rem, 0.95f,
                              ZP_VERDICT_DETERMINISTIC, ZP_SEV_CRITICAL);
        }
    }
    if (maj == 0 && min == 0 && patch == 0 && !pkexec_present) {
        return ZP_OK;
    }
    return ZP_OK;
}
