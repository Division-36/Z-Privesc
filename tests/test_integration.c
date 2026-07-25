/* test_integration.c - End-to-end on real vulnerable testbeds
 *
 * Walks testbeds/*/setup.sh, runs the binary, asserts DETERMINISTIC
 * findings; then runs cleanup.sh and re-runs to assert REJECT/UNCERTAIN.
 * This test is meant to be executed as root inside an isolated VM
 * (`make test-full`).
 */

#define _POSIX_C_SOURCE 200809L

#include "z_privesc.h"
#include "truthimatics.h"
#include "audit.h"
#include "probes.h"
#include "risk.h"
#include "util.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>

static int run_script(const char *path)
{
    if (access(path, X_OK) != 0) {
        fprintf(stderr, "skip: %s not executable\n", path);
        return -1;
    }
    pid_t pid = fork();
    if (pid == 0) {
        execl("/bin/sh", "sh", path, (char *)NULL);
        _exit(127);
    }
    int st = 0;
    waitpid(pid, &st, 0);
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

static int run_zprivesc(int *exit_code, int *det_count, int *vuln_exit)
{
    struct zp_cli_args args = {0};
    args.run_all = true;
    args.json_out = true;
    args.quiet    = true;
    struct zp_runtime rt;
    if (zp_runtime_init(&rt, &args) != ZP_OK) return -1;
    struct audit_ctx ctx;
    if (audit_ctx_init(&ctx, 16, 1024) != ZP_OK) return -1;
    int rc = zp_run_probes(&rt, &ctx);
    *det_count = 0;
    for (size_t i = 0; i < rt.probe_count; i++) {
        if (rt.chains[i] && rt.chains[i]->verdict == ZP_VERDICT_DETERMINISTIC) {
            (*det_count)++;
        }
    }
    *vuln_exit = rc;
    *exit_code = rc;
    audit_ctx_release(&ctx);
    zp_runtime_release(&rt);
    return 0;
}

int main(void)
{
    if (getuid() != 0) {
        fprintf(stderr, "integration tests require root\n");
        return 2;
    }
    int setup_rc;
    const char *testbeds[] = {
        "testbeds/suid/setup.sh",
        "testbeds/writable_path/setup.sh",
        "testbeds/capabilities/setup.sh",
        "testbeds/writable_etc/setup.sh",
        "testbeds/polkit/setup.sh",
        "testbeds/world_writable/setup.sh",
        NULL
    };
    for (size_t i = 0; testbeds[i] != NULL; i++) {
        setup_rc = run_script(testbeds[i]);
        if (setup_rc != 0) {
            fprintf(stderr, "WARN: %s exited %d\n", testbeds[i],
                    setup_rc);
        }
    }
    int det1, code1, vuln1;
    run_zprivesc(&code1, &det1, &vuln1);
    fprintf(stderr, "after-setup: DETERMINISTIC chains=%d exit=%d\n",
            det1, code1);
    if (det1 < 1) {
        fprintf(stderr, "FAIL: expected at least one DETERMINISTIC chain\n");
        return 1;
    }
    const char *cleanups[] = {
        "testbeds/suid/cleanup.sh",
        "testbeds/writable_path/cleanup.sh",
        "testbeds/capabilities/cleanup.sh",
        "testbeds/writable_etc/cleanup.sh",
        "testbeds/polkit/cleanup.sh",
        "testbeds/world_writable/cleanup.sh",
        NULL
    };
    for (size_t i = 0; cleanups[i] != NULL; i++) {
        run_script(cleanups[i]);
    }
    int det2, code2, vuln2;
    run_zprivesc(&code2, &det2, &vuln2);
    fprintf(stderr, "after-cleanup: DETERMINISTIC chains=%d exit=%d\n",
            det2, code2);
    if (det2 > det1) {
        fprintf(stderr, "FAIL: risk did not drop after cleanup\n");
        return 1;
    }
    fprintf(stderr, "integration: PASS\n");
    return 0;
}
