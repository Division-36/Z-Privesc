/*
 * risk.c - CVSS-like risk aggregator
 *
 * Per-finding score = severity-base + (weight * dynamic-range), clamped
 * to [0,10].  Per-probe score is the maximum finding score (worst
 * finding dominates).  Overall score is the maximum probe score, with
 * a small additive bonus when more than one probe is DETERMINISTIC.
 *
 * Author: Zierax (Ziad Salah) <zs.01117875692@gmail.com>
 */

#define _POSIX_C_SOURCE 200809L

#include "z_privesc.h"
#include "risk.h"
#include "truthimatics.h"

#include <math.h>
#include <string.h>

static float sev_base(enum zp_severity s)
{
    switch (s) {
    case ZP_SEV_INFO:     return 0.5f;
    case ZP_SEV_LOW:      return 2.5f;
    case ZP_SEV_MEDIUM:   return 5.0f;
    case ZP_SEV_HIGH:     return 7.5f;
    case ZP_SEV_CRITICAL: return 9.5f;
    }
    return 0.0f;
}

static float sev_range(enum zp_severity s)
{
    switch (s) {
    case ZP_SEV_INFO:     return 1.5f;
    case ZP_SEV_LOW:      return 2.0f;
    case ZP_SEV_MEDIUM:   return 1.5f;
    case ZP_SEV_HIGH:     return 1.0f;
    case ZP_SEV_CRITICAL: return 0.5f;
    }
    return 0.0f;
}

float zp_risk_finding(enum zp_severity sev, float weight)
{
    if (weight < 0.0f) weight = 0.0f;
    if (weight > 1.0f) weight = 1.0f;
    float score = sev_base(sev) + (weight * sev_range(sev));
    if (score < ZP_RISK_MIN) {
        score = ZP_RISK_MIN;
    }
    if (score > ZP_RISK_MAX) {
        score = ZP_RISK_MAX;
    }
    return score;
}

float zp_risk_probe(const struct zp_evidence_chain *c)
{
    if (c == NULL || c->count == 0) {
        return 0.0f;
    }
    float worst = 0.0f;
    struct zp_evidence_link *link = c->head;
    while (link != NULL) {
        float s = zp_risk_finding(link->severity, link->weight);
        if (s > worst) {
            worst = s;
        }
        link = link->next;
    }
    return worst;
}

float zp_risk_overall(const float *probe_scores, size_t n)
{
    if (probe_scores == NULL || n == 0) {
        return 0.0f;
    }
    float worst = 0.0f;
    int   det   = 0;
    for (size_t i = 0; i < n; i++) {
        if (probe_scores[i] > worst) {
            worst = probe_scores[i];
        }
        if (probe_scores[i] >= 5.0f) {
            det++;
        }
    }
    float bonus = 0.0f;
    if (det >= 2) {
        bonus = 0.3f * (float)(det - 1);
        if (bonus > 1.5f) {
            bonus = 1.5f;
        }
    }
    float score = worst + bonus;
    if (score < ZP_RISK_MIN) {
        score = ZP_RISK_MIN;
    }
    if (score > ZP_RISK_MAX) {
        score = ZP_RISK_MAX;
    }
    return score;
}

const char *zp_risk_label(float score)
{
    if (score >= 9.0f) return "CRITICAL";
    if (score >= 7.0f) return "HIGH";
    if (score >= 4.0f) return "MEDIUM";
    if (score >= 1.0f) return "LOW";
    return "INFO";
}

int zp_risk_label_to_int(const char *label)
{
    if (label == NULL) return 0;
    if (strcmp(label, "CRITICAL") == 0) return 4;
    if (strcmp(label, "HIGH")     == 0) return 3;
    if (strcmp(label, "MEDIUM")   == 0) return 2;
    if (strcmp(label, "LOW")      == 0) return 1;
    return 0;
}
