/*
 * truthimatics.h - Evidence-based verdict engine
 *
 * The Truthimatics Public Version engine aggregates individual pieces of
 * evidence collected by probes into a single majority-weighted verdict.
 * Each piece of evidence is a node in a chain; the engine walks the chain,
 * accumulates the weights of all DETERMINISTIC, REJECT, and UNCERTAIN
 * links, and chooses the verdict whose weighted sum dominates the chain.
 *
 * Author: Zierax (Ziad Salah) <zs.01117875692@gmail.com>
 * License: MIT
 */

#ifndef Z_PRIVESC_TRUTHIMATICS_H
#define Z_PRIVESC_TRUTHIMATICS_H

#include <stddef.h>
#include <stdint.h>

enum zp_verdict {
    ZP_VERDICT_DETERMINISTIC = 0,
    ZP_VERDICT_REJECT        = 1,
    ZP_VERDICT_UNCERTAIN     = 2
};

enum zp_severity {
    ZP_SEV_INFO      = 0,
    ZP_SEV_LOW       = 1,
    ZP_SEV_MEDIUM    = 2,
    ZP_SEV_HIGH      = 3,
    ZP_SEV_CRITICAL  = 4
};

struct zp_evidence_link {
    char                id[ZP_EVIDENCE_ID_MAX];
    char                target[ZP_PATH_MAX];
    char                description[ZP_DESC_MAX];
    char                remediation[ZP_REMEDIATION_MAX];
    float               weight;
    enum zp_verdict  verdict;
    enum zp_severity severity;
    struct zp_evidence_link *next;
};

struct zp_evidence_chain {
    struct zp_evidence_link *head;
    struct zp_evidence_link *tail;
    size_t                      count;
    float                       total_weight;
    float                       det_weight;
    float                       rej_weight;
    float                       unc_weight;
    enum zp_verdict          verdict;
    enum zp_severity         max_severity;
    char                        probe_name[ZP_PROBE_NAME_MAX];
};

const char     *zp_verdict_str(enum zp_verdict v);
const char     *zp_severity_str(enum zp_severity s);
enum zp_severity zp_severity_from_str(const char *s);

int             zp_evidence_chain_init(struct zp_evidence_chain *c,
                                          const char *probe_name);
void            zp_evidence_chain_release(struct zp_evidence_chain *c);
int             zp_evidence_add(struct zp_evidence_chain *c,
                                   const char *id,
                                   const char *target,
                                   const char *description,
                                   const char *remediation,
                                   float weight,
                                   enum zp_verdict verdict,
                                   enum zp_severity severity);

enum zp_verdict zp_engine_decide(struct zp_evidence_chain *c);
float           zp_engine_det_share(const struct zp_evidence_chain *c);
float           zp_engine_rej_share(const struct zp_evidence_chain *c);

#endif
