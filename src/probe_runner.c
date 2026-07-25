/*
 * probe_runner.c - Iterate registered probes, collect evidence
 *
 * Builds the per-probe evidence chains, dispatches to the probe
 * functions in a configurable order, applies the Truthimatics engine
 * verdict, and populates the audit context.
 *
 * Author: Zierax (Ziad Salah) <zs.01117875692@gmail.com>
 */

#define _POSIX_C_SOURCE 200809L

#include "z_privesc.h"
#include "probes.h"
#include "truthimatics.h"
#include "audit.h"
#include "risk.h"
#include "util.h"
#include "log.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static const struct zp_probe REGISTRY[] = {
    {"suid",             "SUID/SGID binary scanner",
        zp_probe_suid,               false},
    {"writable_path",    "World-writable $PATH entries",
        zp_probe_writable_path,      false},
    {"capabilities",     "File and process Linux capabilities",
        zp_probe_capabilities,       false},
    {"writable_etc",     "Writable /etc authentication files",
        zp_probe_writable_etc,       false},
    {"docker_socket",    "Exposed Docker control socket",
        zp_probe_docker_socket,      false},
    {"polkit",           "polkit / pkexec misconfiguration",
        zp_probe_polkit,             false},
    {"world_writable",   "World-writable sensitive files / sticky-bit",
        zp_probe_world_writable,     false},
    {"kernel_vuln",      "Kernel version CVE matcher",
        zp_probe_kernel_vuln,        false},
    {"cron",             "Cron job misconfiguration",
        zp_probe_cron,               false},
    {"sudoers",          "Sudoers rule audit",
        zp_probe_sudoers,            false},
    {"ssh_keys",         "SSH private key permissions",
        zp_probe_ssh_keys,           false},
    {"groups",           "Privileged group membership",
        zp_probe_groups,             false},
    {"service",          "Systemd unit file audit",
        zp_probe_service,            false},
    {"kernel_hardening", "Kernel hardening /proc/sys settings",
        zp_probe_kernel_hardening,   false},
    {"process",          "Root process binary audit",
        zp_probe_process,            false},
    {"nfs",              "NFS export misconfiguration",
        zp_probe_nfs,                false},
    {"ld_preload",       "LD_PRELOAD / ld.so.conf audit",
        zp_probe_ld_preload,         false},
};

const struct zp_probe *zp_probe_registry(size_t *count)
{
    if (count != NULL) {
        *count = sizeof(REGISTRY) / sizeof(REGISTRY[0]);
    }
    return REGISTRY;
}

static bool probe_selected(const char *name, const struct zp_runtime *rt)
{
    if (rt->args.run_all) {
        return true;
    }
    for (size_t i = 0; i < rt->args.probe_count; i++) {
        if (strcmp(rt->args.probes[i], name) == 0) {
            return true;
        }
    }
    return false;
}

int zp_runtime_init(struct zp_runtime *rt,
                       const struct zp_cli_args *args)
{
    if (rt == NULL || args == NULL) {
        return ZP_ERR_INVAL;
    }
    memset(rt, 0, sizeof(*rt));
    rt->args = *args;
    rt->uid  = getuid();
    zp_hostname(rt->hostname, sizeof(rt->hostname));
    zp_username(rt->username, sizeof(rt->username));
    zp_kernel_version(rt->kernel, sizeof(rt->kernel));
    rt->start_ns = zp_monotonic_ns();
    size_t total = 0;
    const struct zp_probe *regs = zp_probe_registry(&total);
    for (size_t i = 0; i < total; i++) {
        if (probe_selected(regs[i].name, rt)) {
            if (rt->probe_count >= ZP_MAX_PROBES) {
                break;
            }
            snprintf(rt->probes[rt->probe_count],
                     sizeof(rt->probes[rt->probe_count]),
                     "%s", regs[i].name);
            rt->chains[rt->probe_count] = zp_calloc(
                1, sizeof(struct zp_evidence_chain));
            zp_evidence_chain_init(rt->chains[rt->probe_count],
                                      regs[i].name);
            rt->probe_count++;
        }
    }
    return ZP_OK;
}

void zp_runtime_release(struct zp_runtime *rt)
{
    if (rt == NULL) {
        return;
    }
    for (size_t i = 0; i < rt->probe_count; i++) {
        if (rt->chains[i] != NULL) {
            zp_evidence_chain_release(rt->chains[i]);
            free(rt->chains[i]);
            rt->chains[i] = NULL;
        }
    }
    rt->probe_count = 0;
}

int zp_run_probes(struct zp_runtime *rt, struct audit_ctx *ctx)
{
    if (rt == NULL || ctx == NULL) {
        return ZP_ERR_INVAL;
    }
    size_t total = 0;
    const struct zp_probe *regs = zp_probe_registry(&total);
    int    worst = ZP_EXIT_OK;
    for (size_t i = 0; i < rt->probe_count; i++) {
        const struct zp_probe *p = NULL;
        for (size_t j = 0; j < total; j++) {
            if (strcmp(regs[j].name, rt->probes[i]) == 0) {
                p = &regs[j];
                break;
            }
        }
        if (p == NULL) {
            continue;
        }
        zp_log_progress("[%zu/%zu] %s", i + 1, rt->probe_count,
                           p->name);
        struct zp_evidence_chain *c = rt->chains[i];
        int rc = p->run(c, rt->args.root[0] ? rt->args.root : "/", ctx);
        if (rc != ZP_OK) {
            zp_log_warn("probe %s returned error %d", p->name, rc);
            worst = ZP_EXIT_PROBE;
        }
        enum zp_verdict v = zp_engine_decide(c);
        float ps = zp_risk_probe(c);
        int   idx = audit_ctx_add_probe(ctx, p->name,
                                        zp_verdict_str(v),
                                        c->count, ps);
        struct zp_evidence_link *link = c->head;
        for (size_t k = 0; k < c->count && link != NULL; k++) {
            struct audit_finding f = {
                .id          = link->id,
                .target      = link->target,
                .description = link->description,
                .remediation = link->remediation,
                .weight      = link->weight,
                .severity    = zp_severity_str(link->severity),
                .risk_score  = zp_risk_finding(link->severity,
                                                 link->weight),
            };
            if (audit_ctx_add_finding(ctx, (size_t)idx, &f) != ZP_OK) {
                zp_log_warn("finding buffer full on probe %s",
                               p->name);
                break;
            }
            link = link->next;
        }
        if (v == ZP_VERDICT_DETERMINISTIC) {
            worst = ZP_EXIT_VULN;
        }
    }
    float *scores = zp_calloc(rt->probe_count, sizeof(float));
    for (size_t i = 0; i < rt->probe_count; i++) {
        scores[i] = zp_risk_probe(rt->chains[i]);
        int r = (int)(scores[i] * 10.0f + 0.5f);
        if (r > rt->max_risk_x10) {
            rt->max_risk_x10 = r;
        }
    }
    float overall = zp_risk_overall(scores, rt->probe_count);
    int   ox10    = (int)(overall * 10.0f + 0.5f);
    if (ox10 > rt->max_risk_x10) {
        rt->max_risk_x10 = ox10;
    }
    snprintf(rt->risk_label, sizeof(rt->risk_label), "%s",
             zp_risk_label(overall));
    ctx->overall_risk = overall;
    ctx->risk_label   = rt->risk_label;
    free(scores);
    rt->end_ns = zp_monotonic_ns();
    return worst;
}
