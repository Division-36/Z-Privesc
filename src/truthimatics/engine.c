/*
 * engine.c - Truthimatics verdict engine
 *
 * Computes the majority-weighted verdict of an evidence chain.
 *
 * Algorithm (per Z-Jail / Truthimatics Public Version spec):
 *   1. If chain is empty -> UNCERTAIN
 *   2. If a single link's weight > chain.total * 0.5 -> adopt that link
 *   3. Otherwise, take the verdict whose weighted share is greatest.
 *   4. Tie-breakers: REJECT wins ties with UNCERTAIN, DETERMINISTIC loses
 *      ties with both (to avoid over-reporting).
 *
 * Author: Zierax (Ziad Salah) <zs.01117875692@gmail.com>
 */

#define _POSIX_C_SOURCE 200809L

#include "z_privesc.h"
#include "truthimatics.h"
#include "util.h"
#include "log.h"

#include <string.h>
#include <stddef.h>

float zp_engine_det_share(const struct zp_evidence_chain *c)
{
    if (c == NULL || c->total_weight <= 0.0f) {
        return 0.0f;
    }
    return c->det_weight / c->total_weight;
}

float zp_engine_rej_share(const struct zp_evidence_chain *c)
{
    if (c == NULL || c->total_weight <= 0.0f) {
        return 0.0f;
    }
    return c->rej_weight / c->total_weight;
}

enum zp_verdict zp_engine_decide(struct zp_evidence_chain *c)
{
    if (c == NULL) {
        return ZP_VERDICT_UNCERTAIN;
    }
    if (c->count == 0) {
        c->verdict = ZP_VERDICT_UNCERTAIN;
        return c->verdict;
    }
    if (c->total_weight <= 0.0f) {
        c->verdict = ZP_VERDICT_UNCERTAIN;
        return c->verdict;
    }
    if (c->rej_weight / c->total_weight > 0.5f) {
        c->verdict = ZP_VERDICT_REJECT;
        return c->verdict;
    }
    enum zp_verdict top   = ZP_VERDICT_REJECT;
    float              top_w = c->rej_weight;
    if (c->det_weight > top_w) {
        top   = ZP_VERDICT_DETERMINISTIC;
        top_w = c->det_weight;
    }
    if (c->unc_weight > top_w) {
        top   = ZP_VERDICT_UNCERTAIN;
        top_w = c->unc_weight;
    }
    struct zp_evidence_link *link = c->head;
    while (link != NULL) {
        if (link->weight > c->total_weight * 0.5f) {
            c->verdict = link->verdict;
            return c->verdict;
        }
        link = link->next;
    }
    c->verdict = top;
    return c->verdict;
}
