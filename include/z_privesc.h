/*
 * z_privesc.h - Z-Privesc core definitions
 *
 * Project-wide types, build identifiers, exit codes, and CLI argument
 * structure.  Included by every translation unit.
 *
 * Author: Zierax (Ziad Salah) <zs.01117875692@gmail.com>
 * License: Z-Privesc Public License v1.0
 */

#ifndef Z_PRIVESC_H
#define Z_PRIVESC_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

#ifndef VERSION
#define VERSION                "1.0.0"
#endif

#ifndef BUILD_ID
#define BUILD_ID               "Z-PRIVESC-DEV"
#endif

#define ZP_PROBE_NAME_MAX   32
#define ZP_PATH_MAX         4096
#define ZP_EVIDENCE_ID_MAX  32
#define ZP_DESC_MAX         256
#define ZP_REMEDIATION_MAX  256

#define ZP_OK               0
#define ZP_ERR              (-1)
#define ZP_ERR_OOM          (-2)
#define ZP_ERR_IO           (-3)
#define ZP_ERR_INVAL        (-4)

#define ZP_EXIT_OK          0
#define ZP_EXIT_PROBE       1
#define ZP_EXIT_VULN        2
#define ZP_EXIT_INTERNAL    125

#define ZP_MAX_PROBES       32

struct zp_evidence_chain;
struct audit_ctx;

#include "truthimatics.h"
#include "probes.h"
#include "zp_crypto.h"

struct zp_cli_args {
    bool                run_all;
    char                probes[ZP_MAX_PROBES][ZP_PROBE_NAME_MAX];
    size_t              probe_count;
    char                root[ZP_PATH_MAX];
    bool                json_out;
    bool                html_out;
    bool                quiet;
    bool                verbose;
    bool                show_version;
    bool                show_help;
};

struct zp_runtime {
    struct zp_cli_args      args;
    struct zp_evidence_chain *chains[ZP_MAX_PROBES];
    char                       probes[ZP_MAX_PROBES][ZP_PROBE_NAME_MAX];
    size_t                     probe_count;
    uint64_t                   start_ns;
    uint64_t                   end_ns;
    char                       hostname[256];
    char                       kernel[256];
    char                       username[64];
    uid_t                      uid;
    int                        max_risk_x10;
    char                       risk_label[16];
};

const char     *zp_build_id(void);
const char     *zp_version(void);
int             zp_cli_parse(int argc, char **argv,
                                struct zp_cli_args *out);
void            zp_cli_print_usage(const char *prog);
void            zp_cli_print_version(void);
int             zp_runtime_init(struct zp_runtime *rt,
                                   const struct zp_cli_args *args);
void            zp_runtime_release(struct zp_runtime *rt);
int             zp_run_probes(struct zp_runtime *rt,
                                 struct audit_ctx *ctx);
const struct zp_probe *zp_probe_registry(size_t *count);

#endif
