/* test_truthimatics.c */
#include "test_main.h"
#include "truthimatics.h"
#include "util.h"

int test_truthimatics_empty_chain(void)
{
    ZP_TEST_BEGIN("truthimatics_empty_chain");
    struct zp_evidence_chain c;
    zp_evidence_chain_init(&c, "test");
    ASSERT_EQ_INT(zp_engine_decide(&c), ZP_VERDICT_UNCERTAIN);
    zp_evidence_chain_release(&c);
    ZP_TEST_END("truthimatics_empty_chain", 1);
    return ZP_TEST_PASS;
}

int test_truthimatics_single_deterministic(void)
{
    ZP_TEST_BEGIN("truthimatics_single_deterministic");
    struct zp_evidence_chain c;
    zp_evidence_chain_init(&c, "test");
    zp_evidence_add(&c, "T-1", "/bin/xyz",
        "Test deterministic finding",
        "Remove the offending file",
        0.9f, ZP_VERDICT_DETERMINISTIC, ZP_SEV_HIGH);
    ASSERT_EQ_INT(zp_engine_decide(&c), ZP_VERDICT_DETERMINISTIC);
    zp_evidence_chain_release(&c);
    ZP_TEST_END("truthimatics_single_deterministic", 1);
    return ZP_TEST_PASS;
}

int test_truthimatics_majority_reject(void)
{
    ZP_TEST_BEGIN("truthimatics_majority_reject");
    struct zp_evidence_chain c;
    zp_evidence_chain_init(&c, "test");
    for (int i = 0; i < 5; i++) {
        char id[16];
        snprintf(id, sizeof(id), "R-%d", i);
        zp_evidence_add(&c, id, "/dev/null", "no", "no",
                           0.4f, ZP_VERDICT_REJECT, ZP_SEV_INFO);
    }
    zp_evidence_add(&c, "D-1", "/bin/sh", "yes", "no",
                       0.1f, ZP_VERDICT_DETERMINISTIC, ZP_SEV_LOW);
    ASSERT_EQ_INT(zp_engine_decide(&c), ZP_VERDICT_REJECT);
    zp_evidence_chain_release(&c);
    ZP_TEST_END("truthimatics_majority_reject", 1);
    return ZP_TEST_PASS;
}

int test_truthimatics_dominant_link(void)
{
    ZP_TEST_BEGIN("truthimatics_dominant_link");
    struct zp_evidence_chain c;
    zp_evidence_chain_init(&c, "test");
    for (int i = 0; i < 4; i++) {
        char id[16];
        snprintf(id, sizeof(id), "R-%d", i);
        zp_evidence_add(&c, id, "/dev/null", "no", "no",
                           0.05f, ZP_VERDICT_REJECT, ZP_SEV_INFO);
    }
    zp_evidence_add(&c, "D-1", "/bin/sh", "yes", "no",
                       0.9f, ZP_VERDICT_DETERMINISTIC, ZP_SEV_HIGH);
    ASSERT_EQ_INT(zp_engine_decide(&c), ZP_VERDICT_DETERMINISTIC);
    zp_evidence_chain_release(&c);
    ZP_TEST_END("truthimatics_dominant_link", 1);
    return ZP_TEST_PASS;
}

int test_truthimatics_uncertain_wins(void)
{
    ZP_TEST_BEGIN("truthimatics_uncertain_wins");
    struct zp_evidence_chain c;
    zp_evidence_chain_init(&c, "test");
    zp_evidence_add(&c, "U-1", "/opt/app", "maybe", "investigate",
                       0.5f, ZP_VERDICT_UNCERTAIN, ZP_SEV_MEDIUM);
    zp_evidence_add(&c, "R-1", "/dev/null", "no", "no",
                       0.3f, ZP_VERDICT_REJECT, ZP_SEV_INFO);
    ASSERT_EQ_INT(zp_engine_decide(&c), ZP_VERDICT_UNCERTAIN);
    zp_evidence_chain_release(&c);
    ZP_TEST_END("truthimatics_uncertain_wins", 1);
    return ZP_TEST_PASS;
}

int test_truthimatics_weight_clamp(void)
{
    ZP_TEST_BEGIN("truthimatics_weight_clamp");
    struct zp_evidence_chain c;
    zp_evidence_chain_init(&c, "test");
    zp_evidence_add(&c, "C-1", "/x", "d", "r",
                       5.0f, ZP_VERDICT_DETERMINISTIC, ZP_SEV_HIGH);
    ASSERT_NEAR(c.head->weight, 1.0f, 1e-6);
    zp_evidence_add(&c, "C-2", "/x", "d", "r",
                       -1.0f, ZP_VERDICT_DETERMINISTIC, ZP_SEV_HIGH);
    ASSERT_NEAR(c.head->next->weight, 0.0f, 1e-6);
    zp_evidence_chain_release(&c);
    ZP_TEST_END("truthimatics_weight_clamp", 1);
    return ZP_TEST_PASS;
}

int test_truthimatics_release_releases(void)
{
    ZP_TEST_BEGIN("truthimatics_release_releases");
    struct zp_evidence_chain c;
    zp_evidence_chain_init(&c, "test");
    for (int i = 0; i < 100; i++) {
        char id[16];
        snprintf(id, sizeof(id), "X-%d", i);
        zp_evidence_add(&c, id, "/x", "d", "r",
                           0.1f, ZP_VERDICT_REJECT, ZP_SEV_INFO);
    }
    zp_evidence_chain_release(&c);
    ASSERT_EQ_INT(c.count, 0);
    ASSERT_TRUE(c.head == NULL);
    ZP_TEST_END("truthimatics_release_releases", 1);
    return ZP_TEST_PASS;
}

int test_verdict_strings(void)
{
    ZP_TEST_BEGIN("verdict_strings");
    ASSERT_STR_EQ(zp_verdict_str(ZP_VERDICT_DETERMINISTIC),
                  "DETERMINISTIC");
    ASSERT_STR_EQ(zp_verdict_str(ZP_VERDICT_REJECT), "REJECT");
    ASSERT_STR_EQ(zp_verdict_str(ZP_VERDICT_UNCERTAIN), "UNCERTAIN");
    ZP_TEST_END("verdict_strings", 1);
    return ZP_TEST_PASS;
}

int test_severity_strings(void)
{
    ZP_TEST_BEGIN("severity_strings");
    ASSERT_STR_EQ(zp_severity_str(ZP_SEV_CRITICAL), "CRITICAL");
    ASSERT_STR_EQ(zp_severity_str(ZP_SEV_HIGH), "HIGH");
    ASSERT_STR_EQ(zp_severity_str(ZP_SEV_MEDIUM), "MEDIUM");
    ASSERT_STR_EQ(zp_severity_str(ZP_SEV_LOW), "LOW");
    ASSERT_STR_EQ(zp_severity_str(ZP_SEV_INFO), "INFO");
    ZP_TEST_END("severity_strings", 1);
    return ZP_TEST_PASS;
}
