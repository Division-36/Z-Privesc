/*
 * audit.h - JSON audit emitter
 *
 * Produces a single-schema-validated JSON document describing every
 * probe chain, its verdict, its findings, and the overall risk score.
 * The output conforms to schema `z-privesc.audit/v1`.
 *
 * Author: Zierax (Ziad Salah) <zs.01117875692@gmail.com>
 * License: MIT
 */

#ifndef Z_PRIVESC_AUDIT_H
#define Z_PRIVESC_AUDIT_H

#include <stdio.h>
#include <stdint.h>
#include "z_privesc.h"

struct audit_finding {
    const char                *id;
    const char                *target;
    const char                *description;
    const char                *remediation;
    float                      weight;
    const char                *severity;
    float                      risk_score;
};

struct audit_probe_record {
    const char                *name;
    const char                *verdict;
    size_t                     evidence_count;
    float                      risk_score;
    struct audit_finding      *findings;
    size_t                     finding_count;
};

struct audit_ctx {
    struct audit_probe_record  *probes;
    size_t                      probe_count;
    size_t                      probe_capacity;
    int                         max_findings;
    float                       overall_risk;
    const char                 *risk_label;
    uint64_t                    start_ns;
    uint64_t                    end_ns;
    const char                 *build_id;
    const char                 *kernel;
    const char                 *hostname;
    const char                 *username;
    int                         uid;
};

int  audit_ctx_init(struct audit_ctx *ctx, size_t initial_capacity,
                    int max_findings);
void audit_ctx_release(struct audit_ctx *ctx);
int  audit_ctx_add_probe(struct audit_ctx *ctx, const char *name,
                         const char *verdict, size_t evidence_count,
                         float risk_score);
int  audit_ctx_add_finding(struct audit_ctx *ctx, size_t probe_index,
                           const struct audit_finding *f);
int  audit_emit_json(const struct zp_runtime *rt, FILE *out);
int  audit_emit_html(const struct zp_runtime *rt, FILE *out);

#endif
