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
    { TK(T_EXEC_AS_ROOT),     T_ROOT,            0.97f, "execute code as root" },
    { TK(T_WRITE_SUDOERS),    T_EXEC_AS_ROOT,    0.95f, "append NOPASSWD to sudoers" },
    { TK(T_WRITE_SYSTEMD),    T_EXEC_AS_ROOT,    0.95f, "hijack a root-run systemd unit" },
    { TK(T_WRITE_CRON),       T_EXEC_AS_ROOT,    0.95f, "hijack a root-run cron job" },
    { TK(T_INJECT_PRELOAD),   T_EXEC_AS_ROOT,    0.90f, "LD_PRELOAD into root processes" },
    { TK(T_WRITE_PATH_TROJAN),T_EXEC_AS_ROOT,    0.85f, "plant trojan in writable PATH" },
    { TK(T_CONTAINER_ESCAPE), T_ROOT,            0.85f, "escape container to host root" },
    { TK(T_READ_ROOT_KEY),    T_ROOT,            0.95f, "SSH in as root with stolen key" },
    { TK(T_WRITE_DISK),       T_ROOT,            0.90f, "read/write raw disk for root secrets" },
    { TK(T_SETUID_CAP),       T_EXEC_AS_ROOT,    0.93f, "use file capability to setuid" },
    { TK(T_KERNEL_LPE),       T_ROOT,            0.90f, "run kernel LPE exploit" },
    { TK(T_POLKIT_LPE),       T_ROOT,            0.95f, "exploit polkit/pkexec" },
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

/* Reconstruct the edge chain from an initial token up to `start`,
 * returning the list of (from,to,rule) edges in forward order. */
struct edge {
    int from, to, rule;
};
static int backchain(int start, const int *der, struct edge *out, int max)
{
    int n = 0;
    int cur = start;
    /* start is itself an initial/evidence token with no rule to expand */
    if (der[cur] < 0) return 0;
    while (der[cur] >= 0 && n < max) {
        int ri = der[cur];
        int pre = -1;
        /* single-precondition rules: find the set bit */
        uint32_t p = RULES[ri].pre;
        for (int b = 0; b < T_COUNT; b++)
            if (p & TK(b)) { pre = b; break; }
        out[n].from = pre;
        out[n].to   = cur;
        out[n].rule = ri;
        n++;
        cur = pre;
    }
    /* reverse to forward order */
    for (int i = 0; i < n / 2; i++) {
        struct edge tmp = out[i]; out[i] = out[n - 1 - i]; out[n - 1 - i] = tmp;
    }
    return n;
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
        const char *probe = rt->probes[i];
        size_t k = 0;
        for (struct zp_evidence_link *l = c->head; l != NULL; l = l->next, k++) {
            (void)k;
            map_link(probe, l, &initial, refs, &nrefs);
        }
    }

    int der[T_COUNT];
    for (int t = 0; t < T_COUNT; t++) der[t] = -1;  /* -1 = initial/underived */
    uint32_t mask = initial;
    /* Apply rules on top of the initial (evidence) tokens.  A result that is
     * already present as raw evidence is still "derivable"; we record its
     * derivation (first rule wins) so the path can be reconstructed. */
    int changed = 1;
    while (changed) {
        changed = 0;
        for (int i = 0; i < NRULES; i++) {
            if ((mask & RULES[i].pre) == RULES[i].pre) {
                if (!(mask & TK(RULES[i].result))) {
                    mask |= TK(RULES[i].result);
                    changed = 1;
                }
                if (der[RULES[i].result] < 0)
                    der[RULES[i].result] = i;
            }
        }
    }

    fputs("\"escalation_paths\":[", out);

    if (!(mask & TK(T_ROOT))) {
        fputs("]", out);
        return ZP_OK;
    }

    int paths = 0;
    char (*seen)[64] = zp_calloc(256, 64);
    int nseen = 0;

    /* For every rule whose result is ROOT and whose precondition is
     * reachable, reconstruct one escalation path. */
    for (int i = 0; i < NRULES && paths < 16; i++) {
        if (RULES[i].result != T_ROOT) continue;
        if (!(mask & RULES[i].pre)) continue;

        /* precondition token (single-bit mask) -> token index */
        int pre_tok = (int)__builtin_ctz(RULES[i].pre);
        struct edge edges[64];
        int ne = backchain(pre_tok, der, edges, 64);
        /* append the final ROOT hop (guard against a full edge buffer) */
        if (ne < 64) {
            edges[ne].from = pre_tok;
            edges[ne].to   = T_ROOT;
            edges[ne].rule = i;
            ne++;
        }

        /* dedupe by initial token name */
        const char *root_tok = tok_name(edges[0].from);
        int dup = 0;
        for (int s = 0; s < nseen; s++)
            if (strcmp(seen[s], root_tok) == 0) dup = 1;
        if (dup) continue;
        if (nseen < 256) snprintf(seen[nseen++], sizeof(seen[0]), "%s", root_tok);

        if (paths > 0) fputc(',', out);

        float conf = 1.0f;
        for (int e = 0; e < ne; e++) conf *= RULES[edges[e].rule].p;

        fprintf(out, "\n  {\n");
        fprintf(out, "    \"confidence\": %.3f,\n", (double)conf);
        fprintf(out, "    \"technique\": \"%s -> root\",\n", root_tok);
        fputs("    \"steps\": [", out);
        for (int e = 0; e < ne; e++) {
            if (e > 0) fputc(',', out);
            const struct rule *r = &RULES[edges[e].rule];
            const char *fid = "", *ftgt = "";
            /* attach source finding at the initial hop */
            if (e == 0) {
                for (int q = 0; q < nrefs; q++) {
                    if (refs[q].token == edges[e].from) {
                        fid = refs[q].id; ftgt = refs[q].target; break;
                    }
                }
            }
            fprintf(out, "\n      {\"from\":\"%s\",\"to\":\"%s\","
                         "\"reliability\":%.2f,\"technique\":\"%s\","
                         "\"finding\":",
                    tok_name(edges[e].from), tok_name(edges[e].to),
                    (double)r->p, r->tech);
            if (fid && fid[0]) {
                fputc('"', out);
                for (const unsigned char *p = (const unsigned char *)fid; *p; p++) {
                    if (*p == '"') fputs("\\\"", out); else fputc((int)*p, out);
                }
                fputc('"', out);
            } else fputs("null", out);
            fputs(",\"target\":", out);
            if (ftgt && ftgt[0]) {
                fputc('"', out);
                for (const unsigned char *p = (const unsigned char *)ftgt; *p; p++) {
                    if (*p == '"') fputs("\\\"", out);
                    else if (*p == '\\') fputs("\\\\", out);
                    else fputc((int)*p, out);
                }
                fputc('"', out);
            } else fputs("null", out);
            fputc('}', out);
        }
        fputs("\n    ]\n  }", out);
        paths++;
    }

    if (paths > 0) fputc('\n', out);
    fputs("]", out);
    free(refs);
    free(seen);
    return ZP_OK;
}
