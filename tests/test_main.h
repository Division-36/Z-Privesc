/* test_main.h - shared test macros and helpers */
#ifndef Z_PRIVESC_TEST_MAIN_H
#define Z_PRIVESC_TEST_MAIN_H

#include "z_privesc.h"
#include "truthimatics.h"
#include "risk.h"
#include "audit.h"
#include "util.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#define ZP_TEST_PASS  0
#define ZP_TEST_FAIL  1
#define ZP_TEST_SKIP  77

#ifndef ZP_TEST_BEGIN
#define ZP_TEST_BEGIN(name)                                          \
    do {                                                                \
        fprintf(stderr, "  RUN   %s\n", (name));                       \
    } while (0)
#endif

#ifndef ZP_TEST_END
#define ZP_TEST_END(name, ok)                                        \
    do {                                                                \
        (void)(name); (void)(ok);                                       \
    } while (0)
#endif

#define ASSERT_TRUE(cond)                                               \
    do {                                                                \
        if (!(cond)) {                                                  \
            fprintf(stderr, "    assertion failed: %s (%s:%d)\n",       \
                    #cond, __FILE__, __LINE__);                         \
            return ZP_TEST_FAIL;                                     \
        }                                                               \
    } while (0)

#define ASSERT_FALSE(cond) ASSERT_TRUE(!(cond))

#define ASSERT_EQ_INT(a, b)                                             \
    do {                                                                \
        long long _a = (long long)(a);                                  \
        long long _b = (long long)(b);                                  \
        if (_a != _b) {                                                 \
            fprintf(stderr, "    expected %lld got %lld (%s:%d)\n",     \
                    _b, _a, __FILE__, __LINE__);                        \
            return ZP_TEST_FAIL;                                     \
        }                                                               \
    } while (0)

#define ASSERT_NEAR(a, b, eps)                                          \
    do {                                                                \
        double _a = (double)(a);                                        \
        double _b = (double)(b);                                        \
        if (fabs(_a - _b) > (eps)) {                                    \
            fprintf(stderr, "    expected %.6f got %.6f (%s:%d)\n",     \
                    _b, _a, __FILE__, __LINE__);                        \
            return ZP_TEST_FAIL;                                     \
        }                                                               \
    } while (0)

#define ASSERT_STR_EQ(a, b)                                             \
    do {                                                                \
        const char *_a = (a);                                           \
        const char *_b = (b);                                           \
        if (_a == NULL || _b == NULL || strcmp(_a, _b) != 0) {          \
            fprintf(stderr, "    expected '%s' got '%s' (%s:%d)\n",     \
                    _b ? _b : "(null)", _a ? _a : "(null)",             \
                    __FILE__, __LINE__);                                \
            return ZP_TEST_FAIL;                                     \
        }                                                               \
    } while (0)

int test_truthimatics_empty_chain(void);
int test_truthimatics_single_deterministic(void);
int test_truthimatics_majority_reject(void);
int test_truthimatics_dominant_link(void);
int test_truthimatics_uncertain_wins(void);
int test_truthimatics_weight_clamp(void);
int test_truthimatics_release_releases(void);
int test_verdict_strings(void);
int test_severity_strings(void);

int test_risk_finding_range(void);
int test_risk_probe_empty(void);
int test_risk_probe_worst_dominates(void);
int test_risk_overall_bonus(void);
int test_risk_overall_empty(void);
int test_risk_label_bands(void);
int test_risk_label_to_int(void);
int test_risk_finding_clamp(void);

int test_suid_finds_fake_suid(void);
int test_suid_ignores_symlink(void);
int test_suid_empty_root(void);
int test_suid_dangerous_basename(void);

int test_writable_path_detects_dot(void);
int test_writable_path_detects_world_writable(void);
int test_writable_path_handles_missing(void);
int test_writable_path_uses_tempdir(void);

int test_capabilities_safe_chain(void);
int test_capabilities_proc_status(void);
int test_capabilities_critical_filter(void);

int test_writable_etc_clean(void);
int test_writable_etc_detects_writable_file(void);
int test_writable_etc_detects_writable_dir(void);

int test_docker_socket_missing(void);
int test_docker_socket_handles_no_socket(void);

int test_polkit_missing_pieces(void);
int test_polkit_old_version_match(void);

int test_world_writable_clean(void);
int test_world_writable_sticky_bit(void);

int test_kernel_vuln_old_kernel(void);
int test_kernel_vuln_new_kernel(void);
int test_kernel_vuln_handles_garbage(void);

int test_audit_emits_json(void);
int test_audit_emits_html(void);
int test_audit_add_finding_resize(void);

int test_util_path_join(void);
int test_util_path_normalize(void);
int test_util_hex_encode(void);

#endif
