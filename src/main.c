/*
 * main.c - Z-Privesc command-line entry point
 *
 * Parses arguments, initialises the runtime, dispatches to the probe
 * runner, then emits the requested report (JSON or HTML) and the
 * appropriate exit code.
 *
 * Author: Zierax (Ziad Salah) <zs.01117875692@gmail.com>
 */

#define _POSIX_C_SOURCE 200809L

#include "z_privesc.h"
#include "audit.h"
#include "probes.h"
#include "risk.h"
#include "util.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>

void zp_cli_print_usage(const char *prog)
{
    fprintf(stdout,
"Usage: %s [OPTIONS]\n"
"\n"
"Z-Privesc %s - privilege-escalation audit tool\n"
"Build: %s\n"
"\n"
"Options:\n"
"  --all                 Run all probes (default)\n"
"  --probe=<name>        Run a specific probe (may be repeated)\n"
"                        Names: suid writable_path capabilities writable_etc\n"
"                              docker_socket polkit world_writable kernel_vuln\n"
"                              cron sudoers ssh_keys groups service\n"
"                              kernel_hardening process nfs ld_preload\n"
"  --root=<dir>          Scan alternate filesystem root (containers)\n"
"  --json                Emit JSON audit report to stdout\n"
"  --html                Emit HTML audit report to stdout\n"
"  --quiet               Suppress progress output\n"
"  --verbose             Enable debug-level logging\n"
"  --version             Print build ID and exit\n"
"  --help                Print this help and exit\n"
"\n"
"Exit codes:\n"
"  0   No privilege-escalation paths found\n"
"  1   Probe execution error\n"
"  2   At least one DETERMINISTIC finding (vulnerable)\n"
"  125 Internal error (out of memory, etc.)\n",
            prog ? prog : "z_privesc",
            zp_version(), zp_build_id());
}

void zp_cli_print_version(void)
{
    fprintf(stdout, "z_privesc %s\nbuild: %s\n",
            zp_version(), zp_build_id());
}

static int copy_optarg(char *dst, size_t cap, const char *src)
{
    if (src == NULL) return ZP_ERR_INVAL;
    size_t l = strlen(src);
    if (l >= cap) return ZP_ERR_INVAL;
    memcpy(dst, src, l + 1);
    return ZP_OK;
}

int zp_cli_parse(int argc, char **argv, struct zp_cli_args *out)
{
    if (out == NULL) return ZP_ERR_INVAL;
    memset(out, 0, sizeof(*out));
    out->run_all = true;
    static struct option longopts[] = {
        {"all",       no_argument,       0, 'a'},
        {"probe",     required_argument, 0, 'p'},
        {"root",      required_argument, 0, 'r'},
        {"json",      no_argument,       0, 'j'},
        {"html",      no_argument,       0, 'H'},
        {"quiet",     no_argument,       0, 'q'},
        {"verbose",   no_argument,       0, 'v'},
        {"version",   no_argument,       0, 'V'},
        {"help",      no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };
    int idx = 0;
    int c;
    optind = 1;
    while ((c = getopt_long(argc, argv, "ap:r:jHqvh",
                            longopts, &idx)) != -1) {
        switch (c) {
        case 'a':
            out->run_all = true;
            break;
        case 'p':
            if (out->probe_count >= ZP_MAX_PROBES) {
                fprintf(stderr, "too many --probe arguments\n");
                return ZP_ERR_INVAL;
            }
            if (copy_optarg(out->probes[out->probe_count],
                            ZP_PROBE_NAME_MAX, optarg) != ZP_OK) {
                fprintf(stderr, "probe name too long: %s\n", optarg);
                return ZP_ERR_INVAL;
            }
            out->probe_count++;
            out->run_all = false;
            break;
        case 'r':
            if (copy_optarg(out->root, ZP_PATH_MAX, optarg) !=
                    ZP_OK) {
                fprintf(stderr, "root path too long: %s\n", optarg);
                return ZP_ERR_INVAL;
            }
            break;
        case 'j':
            out->json_out = true;
            break;
        case 'H':
            out->html_out = true;
            break;
        case 'q':
            out->quiet = true;
            break;
        case 'v':
            out->verbose = true;
            break;
        case 'V':
            out->show_version = true;
            break;
        case 'h':
            out->show_help = true;
            break;
        default:
            return ZP_ERR_INVAL;
        }
    }
    if (out->show_help || out->show_version) {
        return ZP_OK;
    }
    if (!out->json_out && !out->html_out) {
        out->json_out = true;
    }
    return ZP_OK;
}

int main(int argc, char **argv)
{
    struct zp_cli_args args;
    if (zp_cli_parse(argc, argv, &args) != ZP_OK) {
        zp_cli_print_usage(argv[0]);
        return ZP_EXIT_PROBE;
    }
    if (args.show_help) {
        zp_cli_print_usage(argv[0]);
        return ZP_EXIT_OK;
    }
    if (args.show_version) {
        zp_cli_print_version();
        return ZP_EXIT_OK;
    }
    zp_log_set_quiet(args.quiet);
    zp_log_set_level(args.verbose ? 0 : 1);
    struct zp_runtime rt;
    if (zp_runtime_init(&rt, &args) != ZP_OK) {
        zp_log_error("runtime init failed");
        return ZP_EXIT_INTERNAL;
    }
    struct audit_ctx ctx;
    if (audit_ctx_init(&ctx, 16, 4096) != ZP_OK) {
        zp_log_error("audit init failed");
        zp_runtime_release(&rt);
        return ZP_EXIT_INTERNAL;
    }
    int rc = zp_run_probes(&rt, &ctx);
    if (args.json_out) {
        audit_emit_json(&rt, stdout);
    }
    if (args.html_out) {
        audit_emit_html(&rt, stdout);
    }
    int exit_code = rc;
    if (rt.max_risk_x10 > 0 && rc == ZP_EXIT_OK) {
        exit_code = ZP_EXIT_VULN;
    } else if (rc == ZP_EXIT_OK) {
        exit_code = ZP_EXIT_OK;
    }
    audit_ctx_release(&ctx);
    zp_runtime_release(&rt);
    return exit_code;
}
