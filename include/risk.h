/*
 * risk.h - CVSS-like risk aggregator
 *
 * Computes a 0.0-10.0 risk score per probe and an overall score for the
 * audit document.  Per-finding scores are derived from severity plus the
 * evidence weight, then aggregated as the worst-finding dominance.
 *
 * Author: Zierax (Ziad Salah) <zs.01117875692@gmail.com>
 * License: MIT
 */

#ifndef Z_PRIVESC_RISK_H
#define Z_PRIVESC_RISK_H

#include "truthimatics.h"

#define ZP_RISK_MAX         10.0f
#define ZP_RISK_MIN         0.0f

float           zp_risk_finding(enum zp_severity sev, float weight);
float           zp_risk_probe(const struct zp_evidence_chain *c);
float           zp_risk_overall(const float *probe_scores, size_t n);
const char     *zp_risk_label(float score);
int             zp_risk_label_to_int(const char *label);

#endif
