/*
 * compose.c - Exploitability Composition Engine
 *
 * See include/compose.h for the model description.  Consumes the same
 * per-probe evidence chains the JSON emitter reads and composes them
 * into privilege-escalation paths via a capability-graph reachability
 * analysis with calibrated exploit-reliability weights.
 *
 * Author: Zierax (Ziad Salah) <zs.01117875692@gmail.com>
 * License: MIT
 */

#define _POSIX_C_SOURCE 200809L

#include "z_privesc.h"
#include "compose.h"
#include "truthimatics.h"
#include "util.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <math.h>

/* ---- privilege tokens (bit indices) ------------------------------- */
enum {
    T_ROOT = 0,
    T_EXEC_AS_ROOT,
    T_WRITE_SUDOERS,
    T_WRITE_SYSTEMD,
    T_WRITE_CRON,
    T_INJECT_PRELOAD,
    T_CONTAINER_ESCAPE,
    T_READ_ROOT_KEY,
    T_WRITE_DISK,
    T_SETUID_CAP,
    T_KERNEL_LPE,
    T_POLKIT_LPE,
    T_WRITE_PATH_TROJAN,
    T_COUNT
};

#define TK(t) ((uint32_t)1u << (t))

static const char *tok_name(int t)
{
    switch (t) {
    case T_ROOT:             return "ROOT";
    case T_EXEC_AS_ROOT:     return "EXEC_AS_ROOT";
    case T_WRITE_SUDOERS:    return "WRITE_SUDOERS";
    case T_WRITE_SYSTEMD:    return "WRITE_SYSTEMD";
    case T_WRITE_CRON:       return "WRITE_CRON";
    case T_INJECT_PRELOAD:   return "INJECT_PRELOAD";
    case T_CONTAINER_ESCAPE: return "CONTAINER_ESCAPE";
    case T_READ_ROOT_KEY:    return "READ_ROOT_KEY";
    case T_WRITE_DISK:       return "WRITE_DISK";
    case T_SETUID_CAP:       return "SETUID_CAP";
    case T_KERNEL_LPE:       return "KERNEL_LPE";
    case T_POLKIT_LPE:       return "POLKIT_LPE";
    case T_WRITE_PATH_TROJAN:return "WRITE_PATH_TROJAN";
    default:                 return "?";
    }
}

/* ---- production rules (calibrated exploit reliability) ------------ */
/* p = P(next state reached | precondition granted). Seeds initialised
 * from the ground-truth study as a first-order proxy and refined by the
 * larger evaluation harness. */
struct rule {
    uint32_t pre;
    int      result;
    float    p;
    const char *tech;
};

static const struct rule RULES[] = {
    /* Weights below are CALIBRATED from the evaluation corpus (evaluation/
       calibrate.py over corpus.local.json, n=14 local slice). They replace the
       original seed priors: rules with no observations retain their seed value.
       Re-run calibrate.py after any corpus change and mirror the result here. */
    { TK(T_EXEC_AS_ROOT),     T_ROOT,            0.857f, "execute code as root" },
    { TK(T_WRITE_SUDOERS),    T_EXEC_AS_ROOT,    0.750f, "append NOPASSWD to sudoers" },
    { TK(T_WRITE_SYSTEMD),    T_EXEC_AS_ROOT,    0.667f, "hijack a root-run systemd unit" },
    { TK(T_WRITE_CRON),       T_EXEC_AS_ROOT,    0.667f, "hijack a root-run cron job" },
    { TK(T_INJECT_PRELOAD),   T_EXEC_AS_ROOT,    0.667f, "LD_PRELOAD into root processes" },
    { TK(T_WRITE_PATH_TROJAN),T_EXEC_AS_ROOT,    0.667f, "plant trojan in writable PATH" },
    { TK(T_CONTAINER_ESCAPE), T_ROOT,            0.750f, "escape container to host root" },
    { TK(T_READ_ROOT_KEY),    T_ROOT,            0.667f, "SSH in as root with stolen key" },
    { TK(T_WRITE_DISK),       T_ROOT,            0.900f, "read/write raw disk for root secrets" },
    { TK(T_SETUID_CAP),       T_EXEC_AS_ROOT,    0.667f, "use file capability to setuid" },
    { TK(T_KERNEL_LPE),       T_ROOT,            0.900f, "run kernel LPE exploit" },
    { TK(T_POLKIT_LPE),       T_ROOT,            0.333f, "exploit polkit/pkexec" },
};
#define NRULES (int)(sizeof(RULES) / sizeof(RULES[0]))

/* ---- finding references (source evidence for a token) ------------- */
struct ref {
    int   token;
    char  id[48];
    char  target[1024];
};

static int link_has(const char *s, const char *needle)
{
    if (s == NULL) return 0;
    return strcasestr(s, needle) != NULL;
}

/* Map one evidence link to zero or more initial tokens. */
static void map_link(const char *probe, const struct zp_evidence_link *l,
                     uint32_t *mask, struct ref *refs, int *nrefs)
{
    const char *t = l->target;
    int tok = -1;

    if (strcmp(probe, "suid") == 0) {
        if (l->weight >= 0.8f) tok = T_EXEC_AS_ROOT;   /* dangerous SUID */
    } else if (strcmp(probe, "sudoers") == 0) {
        tok = T_EXEC_AS_ROOT;
    } else if (strcmp(probe, "groups") == 0) {
        if (link_has(l->id, "docker") || link_has(l->description, "docker") ||
            link_has(l->id, "lxd")    || link_has(l->description, "lxd"))
            tok = T_CONTAINER_ESCAPE;
        else if (link_has(l->id, "disk") || link_has(l->description, "disk"))
            tok = T_WRITE_DISK;
    } else if (strcmp(probe, "capabilities") == 0) {
        if (link_has(l->description, "setuid") || link_has(l->id, "setuid") ||
            link_has(l->description, "dac_override"))
            tok = T_SETUID_CAP;
    } else if (strcmp(probe, "writable_etc") == 0 ||
               strcmp(probe, "world_writable") == 0) {
        if (link_has(t, "sudoers"))        tok = T_WRITE_SUDOERS;
        else if (link_has(t, "systemd"))    tok = T_WRITE_SYSTEMD;
        else if (link_has(t, "cron"))       tok = T_WRITE_CRON;
        else if (link_has(t, "ld.so") || link_has(t, "preload"))
            tok = T_INJECT_PRELOAD;
    } else if (strcmp(probe, "service") == 0) {
        tok = T_WRITE_SYSTEMD;
    } else if (strcmp(probe, "cron") == 0) {
        tok = T_WRITE_CRON;
    } else if (strcmp(probe, "ld_preload") == 0) {
        tok = T_INJECT_PRELOAD;
    } else if (strcmp(probe, "ssh_keys") == 0) {
        tok = T_READ_ROOT_KEY;
    } else if (strcmp(probe, "process") == 0) {
        /* Only a world-writable, root-owned executable is a direct root-exec
         * vector. Benign signals a process probe may surface (deleted binary,
         * unknown binary, etc.) are NOT escalations and must not be composed. */
        if (link_has(l->description, "writable") || link_has(l->target, "writable") ||
            link_has(l->id, "WRITABLE"))
            tok = T_EXEC_AS_ROOT;
    } else if (strcmp(probe, "kernel_vuln") == 0) {
        tok = T_KERNEL_LPE;
    } else if (strcmp(probe, "polkit") == 0) {
        tok = T_POLKIT_LPE;
    } else if (strcmp(probe, "docker_socket") == 0) {
        tok = T_CONTAINER_ESCAPE;
    } else if (strcmp(probe, "writable_path") == 0) {
        tok = T_WRITE_PATH_TROJAN;
    } else if (strcmp(probe, "nfs") == 0) {
        tok = T_ROOT;            /* no_root_squash => root on the server */
    }

    if (tok < 0) return;
    *mask |= TK(tok);
    if (*nrefs < 256) {
        struct ref *r = &refs[(*nrefs)++];
        r->token = tok;
        const char *idp = l->id[0] ? l->id : "";
        const char *tgt = t[0] ? t : "";
        size_t il = strlen(idp), tl = strlen(tgt);
        size_t in = il < sizeof(r->id) - 1 ? il : sizeof(r->id) - 1;
        size_t tn = tl < sizeof(r->target) - 1 ? tl : sizeof(r->target) - 1;
        memcpy(r->id, idp, in); r->id[in] = 0;
        memcpy(r->target, tgt, tn); r->target[tn] = 0;
    }
}

/* ---- reachability fixpoint with derivation ------------------------ */
/* der[t] = index of rule that derived token t, or -1 if initial.
 * The fixpoint itself is applied inline in zp_compose_json over the
 * initial mask gathered from the runtime chains. */

/* Edge in a reconstructed escalation chain. */
struct edge {
    int from, to, rule;
};

/* Emit a JSON string or the literal null, escaping '"' and '\\'. */
static void emit_json_str(FILE *out, const char *s)
{
    if (s && *s) {
        fputc('"', out);
        for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
            if (*p == '"') fputs("\\\"", out);
            else if (*p == '\\') fputs("\\\\", out);
            else fputc((int)*p, out);
        }
        fputc('"', out);
    } else {
        fputs("null", out);
    }
}

/* Run the fixpoint starting from a single seed token, recording the deriving
 * rule per token in der[]. Returns 1 if ROOT is reachable from the seed.
 * Enumerating per-evidence-token (rather than one global fixpoint) lets us
 * reconstruct a distinct, correctly-rooted chain for each entry technique
 * instead of collapsing every route into the first-derived one. */
static int fixpoint_from(int seed, int *der)
{
    for (int t = 0; t < T_COUNT; t++) der[t] = -1;
    uint32_t mask = TK(seed);
    int changed = 1;
    while (changed) {
        changed = 0;
        for (int i = 0; i < NRULES; i++) {
            if ((mask & RULES[i].pre) == RULES[i].pre) {
                int res = RULES[i].result;
                if (!(mask & TK(res))) { mask |= TK(res); changed = 1; }
                if (der[res] < 0) der[res] = i;
            }
        }
    }
    return (mask & TK(T_ROOT)) ? 1 : 0;
}

int zp_compose_json(const struct zp_runtime *rt, FILE *out)
{
    if (rt == NULL || out == NULL) return ZP_ERR_INVAL;

    uint32_t initial = 0;
    struct ref *refs = zp_calloc(256, sizeof(struct ref));
    if (refs == NULL) return ZP_ERR_OOM;
    int nrefs = 0;

    for (size_t i = 0; i < rt->probe_count; i++) {
        struct zp_evidence_chain *c = rt->chains[i];
        if (c == NULL) continue;
        /* A probe that decided CLEAN/REJECT carries only negative evidence and
         * must not be mapped to any escalation token: otherwise we would compose
         * a root path out of a "no misconfiguration found" result and report a
         * false escalation. */
        if (c->verdict == ZP_VERDICT_REJECT) continue;
        const char *probe = rt->probes[i];
        for (struct zp_evidence_link *l = c->head; l != NULL; l = l->next) {
            if (l->verdict == ZP_VERDICT_REJECT || l->severity == ZP_SEV_INFO) continue;
            map_link(probe, l, &initial, refs, &nrefs);
        }
    }

    /* ---- escalation-path enumeration ---------------------------------- *
     * For every evidence (initial) token that can reach ROOT, reconstruct a
     * distinct chain rooted at that token. This emits one path per entry
     * technique (e.g. sudoers vs SUID both reaching EXEC_AS_ROOT are reported
     * separately) and labels every step with its rule reliability. The engine
     * depends only on the audit evidence graph and on no external or
     * kernel-specific facility, so the composition result is portable across
     * any Linux kernel/distro where the same misconfigurations are observed. */
    fputs("\"escalation_paths\":[", out);

    int paths = 0;
    int seen_leaf[64];
    int nseen = 0;

    for (int t = 0; t < T_COUNT && paths < 24; t++) {
        if (!(initial & TK(t))) continue;
        /* one representative path per evidence technique */
        int dup = 0;
        for (int s = 0; s < nseen; s++)
            if (seen_leaf[s] == t) { dup = 1; break; }
        if (dup) continue;

        int der[T_COUNT];
        if (!fixpoint_from(t, der)) continue;   /* this evidence cannot reach root */
        seen_leaf[nseen++] = t;
        if (paths > 0) fputc(',', out);

        struct edge edges[64];
        int ne = 0;
        if (t != (int)T_ROOT) {
            int cur = (int)T_ROOT;
            while (cur != t && der[cur] >= 0 && ne < 63) {
                int ri = der[cur];
                int pre = -1;
                uint32_t p = RULES[ri].pre;
                for (int b = 0; b < T_COUNT; b++)
                    if (p & TK(b)) { pre = b; break; }
                edges[ne].from = pre;
                edges[ne].to   = cur;
                edges[ne].rule = ri;
                ne++;
                cur = pre;
            }
            for (int i = 0; i < ne / 2; i++) {
                struct edge tmp = edges[i];
                edges[i] = edges[ne - 1 - i];
                edges[ne - 1 - i] = tmp;
            }
        }

        float conf = 1.0f;
        for (int e = 0; e < ne; e++) conf *= RULES[edges[e].rule].p;

        const char *leaf_name = tok_name(t);
        const char *fid = "", *ftgt = "";
        for (int q = 0; q < nrefs; q++)
            if (refs[q].token == t) { fid = refs[q].id; ftgt = refs[q].target; break; }

        fprintf(out, "\n  {\n");
        fprintf(out, "    \"confidence\": %.3f,\n", (double)conf);
        if (t == (int)T_ROOT)
            fprintf(out, "    \"technique\": \"ROOT\",\n");
        else
            fprintf(out, "    \"technique\": \"%s -> root\",\n", leaf_name);
        fputs("    \"steps\": [", out);

        if (ne == 0) {
            /* direct grant: the evidence token is already root */
            fputs("\n      {\"from\":\"ROOT\",\"to\":\"ROOT\",\"reliability\":1.00,"
                  "\"technique\":\"direct grant\",\"finding\":", out);
            emit_json_str(out, fid);
            fputs(",\"target\":", out);
            emit_json_str(out, ftgt);
            fputc('}', out);
        } else {
            for (int e = 0; e < ne; e++) {
                if (e > 0) fputc(',', out);
                const struct rule *r = &RULES[edges[e].rule];
                fprintf(out, "\n      {\"from\":\"%s\",\"to\":\"%s\","
                             "\"reliability\":%.2f,\"technique\":\"%s\","
                             "\"finding\":",
                        tok_name(edges[e].from), tok_name(edges[e].to),
                        (double)r->p, r->tech);
                emit_json_str(out, (edges[e].from == t) ? fid : "");
                fputs(",\"target\":", out);
                emit_json_str(out, (edges[e].from == t) ? ftgt : "");
                fputc('}', out);
            }
        }
        fputs("\n    ]\n  }", out);
        paths++;
    }

    if (paths > 0) fputc('\n', out);
    fputs("]", out);
    free(refs);
    return ZP_OK;
}
