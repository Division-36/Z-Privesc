/*
 * audit.c - JSON audit emitter
 *
 * Walks the runtime's probe chains, serialises them into a stable JSON
 * document conforming to schema `z-privesc.audit/v1`, and writes the
 * result to the supplied stream.
 *
 * Author: Zierax (Ziad Salah) <zs.01117875692@gmail.com>
 */

#define _POSIX_C_SOURCE 200809L

#include "z_privesc.h"
#include "audit.h"
#include "truthimatics.h"
#include "probes.h"
#include "util.h"
#include "risk.h"
#include "log.h"
#include "compose.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <inttypes.h>
#include <time.h>

static void json_escape(FILE *out, const char *s)
{
    if (s == NULL) {
        fputs("null", out);
        return;
    }
    fputc('"', out);
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        unsigned char c = *p;
        switch (c) {
        case '"':  fputs("\\\"", out); break;
        case '\\': fputs("\\\\", out); break;
        case '\b': fputs("\\b",  out); break;
        case '\f': fputs("\\f",  out); break;
        case '\n': fputs("\\n",  out); break;
        case '\r': fputs("\\r",  out); break;
        case '\t': fputs("\\t",  out); break;
        default:
            if (c < 0x20) {
                fprintf(out, "\\u%04x", c);
            } else {
                fputc((int)c, out);
            }
        }
    }
    fputc('"', out);
}

static void json_string_or_null(FILE *out, const char *key, const char *val)
{
    fprintf(out, "\"%s\":", key);
    json_escape(out, val);
}

int audit_ctx_init(struct audit_ctx *ctx, size_t initial_capacity,
                   int max_findings)
{
    if (ctx == NULL) {
        return ZP_ERR_INVAL;
    }
    memset(ctx, 0, sizeof(*ctx));
    if (initial_capacity < 1) {
        initial_capacity = 8;
    }
    ctx->probes = zp_calloc(initial_capacity,
                               sizeof(struct audit_probe_record));
    ctx->probe_capacity = initial_capacity;
    ctx->max_findings   = max_findings > 0 ? max_findings : 1024;
    return ZP_OK;
}

void audit_ctx_release(struct audit_ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    for (size_t i = 0; i < ctx->probe_count; i++) {
        struct audit_probe_record *p = &ctx->probes[i];
        for (size_t j = 0; j < p->finding_count; j++) {
            struct audit_finding *f = &p->findings[j];
            free((void *)f->id);
            free((void *)f->target);
            free((void *)f->description);
            free((void *)f->remediation);
            free((void *)f->severity);
        }
        free(p->findings);
        free((void *)p->name);
        free((void *)p->verdict);
    }
    free(ctx->probes);
    memset(ctx, 0, sizeof(*ctx));
}

int audit_ctx_add_probe(struct audit_ctx *ctx, const char *name,
                        const char *verdict, size_t evidence_count,
                        float risk_score)
{
    if (ctx == NULL || name == NULL || verdict == NULL) {
        return ZP_ERR_INVAL;
    }
    if (ctx->probe_count >= ctx->probe_capacity) {
        size_t new_cap = ctx->probe_capacity * 2;
        struct audit_probe_record *np = zp_calloc(
            new_cap, sizeof(struct audit_probe_record));
        memcpy(np, ctx->probes,
               ctx->probe_count * sizeof(struct audit_probe_record));
        free(ctx->probes);
        ctx->probes = np;
        ctx->probe_capacity = new_cap;
    }
    struct audit_probe_record *rec = &ctx->probes[ctx->probe_count++];
    rec->name           = zp_strdup(name);
    rec->verdict        = zp_strdup(verdict);
    rec->evidence_count = evidence_count;
    rec->risk_score     = risk_score;
    return (int)(ctx->probe_count - 1);
}

int audit_ctx_add_finding(struct audit_ctx *ctx, size_t probe_index,
                          const struct audit_finding *f)
{
    if (ctx == NULL || probe_index >= ctx->probe_count || f == NULL) {
        return ZP_ERR_INVAL;
    }
    struct audit_probe_record *rec = &ctx->probes[probe_index];
    if ((int)(rec->finding_count + 1) > ctx->max_findings) {
        return ZP_ERR_INVAL;
    }
    struct audit_finding *nf = zp_calloc(rec->finding_count + 1,
                                            sizeof(struct audit_finding));
    if (rec->finding_count > 0) {
        memcpy(nf, rec->findings,
               rec->finding_count * sizeof(struct audit_finding));
    }
    nf[rec->finding_count].id          = zp_strdup(f->id);
    nf[rec->finding_count].target      = zp_strdup(f->target);
    nf[rec->finding_count].description = zp_strdup(f->description);
    nf[rec->finding_count].remediation = zp_strdup(f->remediation);
    nf[rec->finding_count].weight      = f->weight;
    nf[rec->finding_count].severity    = zp_strdup(f->severity);
    nf[rec->finding_count].risk_score  = f->risk_score;
    free(rec->findings);
    rec->findings = nf;
    rec->finding_count++;
    return ZP_OK;
}

int audit_emit_json(const struct zp_runtime *rt, FILE *out)
{
    if (rt == NULL || out == NULL) {
        return ZP_ERR_INVAL;
    }
    fputs("{\n", out);
    json_string_or_null(out, "schema",        "z-privesc.audit/v1");
    fprintf(out, ",\n");
    json_string_or_null(out, "build_id",      rt->args.show_version
                                              ? zp_build_id() : "n/a");
    fprintf(out, ",\n");
    fprintf(out, "\"timestamp\": %" PRIu64 ",\n", (uint64_t)time(NULL));
    fprintf(out, "\"duration_ns\": %" PRIu64 ",\n",
            rt->end_ns - rt->start_ns);
    json_string_or_null(out, "hostname", rt->hostname);
    fprintf(out, ",\n");
    json_string_or_null(out, "kernel",   rt->kernel);
    fprintf(out, ",\n");
    json_string_or_null(out, "user",     rt->username);
    fprintf(out, ",\n");
    fprintf(out, "\"uid\": %d,\n", (int)rt->uid);
    fprintf(out, "\"overall_risk\": %.2f,\n", rt->max_risk_x10 / 10.0f);
    json_string_or_null(out, "risk_label", rt->risk_label);
    fprintf(out, ",\n");
    fputs("\"probes\": [", out);
    for (size_t i = 0; i < rt->probe_count; i++) {
        struct zp_evidence_chain *c = rt->chains[i];
        const char *verdict = zp_verdict_str(
            c ? c->verdict : ZP_VERDICT_UNCERTAIN);
        float ps = c ? zp_risk_probe(c) : 0.0f;
        if (i > 0) fputc(',', out);
        fprintf(out, "\n  {\n");
        fprintf(out, "    \"name\": ");
        json_escape(out, rt->probes[i]);
        fprintf(out, ",\n");
        fprintf(out, "    \"verdict\": ");
        json_escape(out, verdict);
        fprintf(out, ",\n");
        fprintf(out, "    \"evidence_count\": %zu,\n",
                c ? c->count : (size_t)0);
        fprintf(out, "    \"risk_score\": %.2f,\n", ps);
        fprintf(out, "    \"findings\": [");
        size_t fc = c ? c->count : (size_t)0;
        for (size_t j = 0; j < fc; j++) {
            struct zp_evidence_link *link = NULL;
            size_t k = 0;
            for (link = c->head; link != NULL && k < j;
                 link = link->next, k++) {
            }
            if (link == NULL) {
                break;
            }
            if (j > 0) fputc(',', out);
            fprintf(out, "\n      {");
            fprintf(out, "\"id\":");
            json_escape(out, link->id);
            fprintf(out, ",\"target\":");
            json_escape(out, link->target);
            fprintf(out, ",\"weight\":%.2f", (double)link->weight);
            fprintf(out, ",\"severity\":");
            json_escape(out, zp_severity_str(link->severity));
            fprintf(out, ",\"description\":");
            json_escape(out, link->description);
            fprintf(out, ",\"remediation\":");
            json_escape(out, link->remediation);
            fprintf(out, ",\"risk_score\":%.2f",
                    (double)zp_risk_finding(link->severity,
                                               link->weight));
            fputc('}', out);
        }
        if (fc > 0) fputc('\n', out);
        fprintf(out, "    ]\n  }");
    }
    if (rt->probe_count > 0) fputc('\n', out);
    fputs("],\n", out);
    zp_compose_json(rt, out);
    fputs("\n}\n", out);
    return ZP_OK;
}

int audit_emit_html(const struct zp_runtime *rt, FILE *out)
{
    if (rt == NULL || out == NULL) {
        return ZP_ERR_INVAL;
    }
    fprintf(out, "<!doctype html><html><head><meta charset=\"utf-8\">");
    fprintf(out, "<title>Z-Privesc Audit</title>");
    fprintf(out,
        "<style>body{font-family:sans-serif;margin:2em;}"
        "table{border-collapse:collapse;width:100%%;}"
        "th,td{border:1px solid #ccc;padding:.4em;text-align:left;}"
        "th{background:#eee;}"
        ".crit{color:#b00;font-weight:bold;}"
        ".high{color:#c50;}"
        ".med{color:#a80;}"
        ".low{color:#080;}</style></head><body>");
    fprintf(out, "<h1>Z-Privesc Audit</h1>");
    fprintf(out, "<p>Build: %s<br>Host: %s<br>Kernel: %s<br>User: %s</p>",
            zp_build_id(), rt->hostname, rt->kernel, rt->username);
    fprintf(out, "<p>Overall risk: <b>%s (%.1f)</b></p>",
            rt->risk_label, rt->max_risk_x10 / 10.0f);
    fprintf(out, "<table><tr><th>Probe</th><th>Verdict</th>"
                 "<th>Evidence</th><th>Risk</th></tr>");
    for (size_t i = 0; i < rt->probe_count; i++) {
        struct zp_evidence_chain *c = rt->chains[i];
        const char *v = zp_verdict_str(
            c ? c->verdict : ZP_VERDICT_UNCERTAIN);
        float ps = c ? zp_risk_probe(c) : 0.0f;
        fprintf(out, "<tr><td>%s</td><td>%s</td><td>%zu</td>"
                     "<td>%.1f</td></tr>",
                rt->probes[i], v, c ? c->count : (size_t)0, ps);
    }
    fprintf(out, "</table></body></html>");
    return ZP_OK;
}
