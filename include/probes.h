/*
 * probes.h - Probe interface and registry
 *
 * A probe is a self-contained audit module that scans a single
 * privilege-escalation category (SUID binaries, writable PATH, etc.).
 * Every probe implements the same signature and is registered in the
 * global probe table for the runner to iterate over.
 *
 * Author: Zierax (Ziad Salah) <zs.01117875692@gmail.com>
 * License: Z-Privesc Public License v1.0
 */

#ifndef Z_PRIVESC_PROBES_H
#define Z_PRIVESC_PROBES_H

#include "truthimatics.h"

struct audit_ctx;

typedef int (*zp_probe_fn)(struct zp_evidence_chain *chain,
                              const char *root,
                              struct audit_ctx *ctx);

struct zp_probe {
    const char     *name;
    const char     *description;
    zp_probe_fn  run;
    bool            requires_root;
};

int  zp_probe_suid(struct zp_evidence_chain *c,
                      const char *root, struct audit_ctx *ctx);
int  zp_probe_writable_path(struct zp_evidence_chain *c,
                               const char *root, struct audit_ctx *ctx);
int  zp_probe_capabilities(struct zp_evidence_chain *c,
                              const char *root, struct audit_ctx *ctx);
int  zp_probe_writable_etc(struct zp_evidence_chain *c,
                              const char *root, struct audit_ctx *ctx);
int  zp_probe_docker_socket(struct zp_evidence_chain *c,
                               const char *root, struct audit_ctx *ctx);
int  zp_probe_polkit(struct zp_evidence_chain *c,
                        const char *root, struct audit_ctx *ctx);
int  zp_probe_world_writable(struct zp_evidence_chain *c,
                                const char *root, struct audit_ctx *ctx);
int  zp_probe_kernel_vuln(struct zp_evidence_chain *c,
                             const char *root, struct audit_ctx *ctx);
int  zp_probe_cron(struct zp_evidence_chain *c,
                      const char *root, struct audit_ctx *ctx);
int  zp_probe_sudoers(struct zp_evidence_chain *c,
                         const char *root, struct audit_ctx *ctx);
int  zp_probe_ssh_keys(struct zp_evidence_chain *c,
                          const char *root, struct audit_ctx *ctx);
int  zp_probe_groups(struct zp_evidence_chain *c,
                        const char *root, struct audit_ctx *ctx);
int  zp_probe_service(struct zp_evidence_chain *c,
                         const char *root, struct audit_ctx *ctx);
int  zp_probe_kernel_hardening(struct zp_evidence_chain *c,
                                  const char *root, struct audit_ctx *ctx);
int  zp_probe_process(struct zp_evidence_chain *c,
                         const char *root, struct audit_ctx *ctx);
int  zp_probe_nfs(struct zp_evidence_chain *c,
                     const char *root, struct audit_ctx *ctx);
int  zp_probe_ld_preload(struct zp_evidence_chain *c,
                            const char *root, struct audit_ctx *ctx);

#endif
