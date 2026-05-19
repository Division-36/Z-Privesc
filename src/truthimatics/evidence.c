/*
 * evidence.c - Evidence chain operations
 *
 * Implements the singly-linked list of evidence links used by every
 * probe.  Links are owned by the chain; they are released as a single
 * block in zp_evidence_chain_release.
 *
 * Author: Zierax (Ziad Salah) <zs.01117875692@gmail.com>
 */

#define _POSIX_C_SOURCE 200809L

#include "z_privesc.h"
#include "truthimatics.h"
#include "util.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char *zp_verdict_str(enum zp_verdict v)
{
    switch (v) {
    case ZP_VERDICT_DETERMINISTIC: return "DETERMINISTIC";
    case ZP_VERDICT_REJECT:        return "REJECT";
    case ZP_VERDICT_UNCERTAIN:     return "UNCERTAIN";
    }
    return "UNKNOWN";
}

const char *zp_severity_str(enum zp_severity s)
{
    switch (s) {
    case ZP_SEV_INFO:     return "INFO";
    case ZP_SEV_LOW:      return "LOW";
    case ZP_SEV_MEDIUM:   return "MEDIUM";
    case ZP_SEV_HIGH:     return "HIGH";
    case ZP_SEV_CRITICAL: return "CRITICAL";
    }
    return "INFO";
}

enum zp_severity zp_severity_from_str(const char *s)
{
    if (s == NULL) {
        return ZP_SEV_INFO;
    }
    if (strcmp(s, "CRITICAL") == 0) return ZP_SEV_CRITICAL;
    if (strcmp(s, "HIGH")     == 0) return ZP_SEV_HIGH;
    if (strcmp(s, "MEDIUM")   == 0) return ZP_SEV_MEDIUM;
    if (strcmp(s, "LOW")      == 0) return ZP_SEV_LOW;
    return ZP_SEV_INFO;
}

static void copy_bounded(char *dst, size_t cap, const char *src)
{
    if (cap == 0) {
        return;
    }
    if (src == NULL) {
        dst[0] = '\0';
        return;
    }
    size_t l = strlen(src);
    if (l >= cap) {
        l = cap - 1;
    }
    memcpy(dst, src, l);
    dst[l] = '\0';
}

int zp_evidence_chain_init(struct zp_evidence_chain *c,
                              const char *probe_name)
{
    if (c == NULL) {
        return ZP_ERR_INVAL;
    }
    memset(c, 0, sizeof(*c));
    copy_bounded(c->probe_name, sizeof(c->probe_name), probe_name);
    c->verdict      = ZP_VERDICT_UNCERTAIN;
    c->max_severity = ZP_SEV_INFO;
    return ZP_OK;
}

void zp_evidence_chain_release(struct zp_evidence_chain *c)
{
    if (c == NULL) {
        return;
    }
    struct zp_evidence_link *link = c->head;
    while (link != NULL) {
        struct zp_evidence_link *next = link->next;
        free(link);
        link = next;
    }
    c->head         = NULL;
    c->tail         = NULL;
    c->count        = 0;
    c->total_weight = 0.0f;
    c->det_weight   = 0.0f;
    c->rej_weight   = 0.0f;
    c->unc_weight   = 0.0f;
}

int zp_evidence_add(struct zp_evidence_chain *c,
                       const char *id,
                       const char *target,
                       const char *description,
                       const char *remediation,
                       float weight,
                       enum zp_verdict verdict,
                       enum zp_severity severity)
{
    if (c == NULL || id == NULL) {
        return ZP_ERR_INVAL;
    }
    if (weight < 0.0f) {
        weight = 0.0f;
    }
    if (weight > 1.0f) {
        weight = 1.0f;
    }
    struct zp_evidence_link *link = zp_calloc(1, sizeof(*link));
    copy_bounded(link->id,          sizeof(link->id),          id);
    copy_bounded(link->target,      sizeof(link->target),      target);
    copy_bounded(link->description, sizeof(link->description), description);
    copy_bounded(link->remediation, sizeof(link->remediation), remediation);
    link->weight    = weight;
    link->verdict   = verdict;
    link->severity  = severity;
    link->next      = NULL;
    if (c->tail == NULL) {
        c->head = link;
        c->tail = link;
    } else {
        c->tail->next = link;
        c->tail       = link;
    }
    c->count++;
    c->total_weight += weight;
    if (verdict == ZP_VERDICT_DETERMINISTIC) {
        c->det_weight += weight;
    } else if (verdict == ZP_VERDICT_REJECT) {
        c->rej_weight += weight;
    } else {
        c->unc_weight += weight;
    }
    if ((int)severity > (int)c->max_severity) {
        c->max_severity = severity;
    }
    return ZP_OK;
}
/* Severity string conversion helper */
