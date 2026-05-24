/* test_risk.c */
#include "test_main.h"
#include "risk.h"
#include "truthimatics.h"
#include <math.h>

int test_risk_finding_range(void)
{
    ZP_TEST_BEGIN("risk_finding_range");
    for (int s = ZP_SEV_INFO; s <= ZP_SEV_CRITICAL; s++) {
        for (float w = 0.0f; w <= 1.01f; w += 0.1f) {
            float r = zp_risk_finding((enum zp_severity)s, w);
            ASSERT_TRUE(r >= 0.0f);
            ASSERT_TRUE(r <= 10.0f);
            ASSERT_FALSE(isnan(r));
        }
    }
    ZP_TEST_END("risk_finding_range", 1);
    return ZP_TEST_PASS;
}

int test_risk_probe_empty(void)
{
    ZP_TEST_BEGIN("risk_probe_empty");
    struct zp_evidence_chain c;
    zp_evidence_chain_init(&c, "test");
    ASSERT_NEAR(zp_risk_probe(&c), 0.0f, 1e-6);
    zp_evidence_chain_release(&c);
    ZP_TEST_END("risk_probe_empty", 1);
    return ZP_TEST_PASS;
}

int test_risk_probe_worst_dominates(void)
{
    ZP_TEST_BEGIN("risk_probe_worst_dominates");
    struct zp_evidence_chain c;
    zp_evidence_chain_init(&c, "test");
    zp_evidence_add(&c, "L-1", "/x", "d", "r",
                       0.2f, ZP_VERDICT_DETERMINISTIC, ZP_SEV_LOW);
    zp_evidence_add(&c, "C-1", "/y", "d", "r",
                       0.9f, ZP_VERDICT_DETERMINISTIC,
                       ZP_SEV_CRITICAL);
    zp_evidence_add(&c, "I-1", "/z", "d", "r",
                       0.5f, ZP_VERDICT_REJECT, ZP_SEV_INFO);
    float score = zp_risk_probe(&c);
    ASSERT_TRUE(score > 9.0f);
    zp_evidence_chain_release(&c);
    ZP_TEST_END("risk_probe_worst_dominates", 1);
    return ZP_TEST_PASS;
}

int test_risk_overall_bonus(void)
{
    ZP_TEST_BEGIN("risk_overall_bonus");
    float scores[] = { 7.0f, 7.0f, 0.0f, 0.0f };
    float s = zp_risk_overall(scores, 4);
    ASSERT_TRUE(s > 7.0f);
    float single[] = { 7.0f };
    float s2 = zp_risk_overall(single, 1);
    ASSERT_NEAR(s2, 7.0f, 1e-6);
    ZP_TEST_END("risk_overall_bonus", 1);
    return ZP_TEST_PASS;
}

int test_risk_overall_empty(void)
{
    ZP_TEST_BEGIN("risk_overall_empty");
    ASSERT_NEAR(zp_risk_overall(NULL, 0), 0.0f, 1e-6);
    float s[1] = { 0.0f };
    ASSERT_NEAR(zp_risk_overall(s, 1), 0.0f, 1e-6);
    ZP_TEST_END("risk_overall_empty", 1);
    return ZP_TEST_PASS;
}

int test_risk_label_bands(void)
{
    ZP_TEST_BEGIN("risk_label_bands");
    ASSERT_STR_EQ(zp_risk_label(9.5f), "CRITICAL");
    ASSERT_STR_EQ(zp_risk_label(7.0f), "HIGH");
    ASSERT_STR_EQ(zp_risk_label(4.0f), "MEDIUM");
    ASSERT_STR_EQ(zp_risk_label(1.0f), "LOW");
    ASSERT_STR_EQ(zp_risk_label(0.0f), "INFO");
    ZP_TEST_END("risk_label_bands", 1);
    return ZP_TEST_PASS;
}

int test_risk_label_to_int(void)
{
    ZP_TEST_BEGIN("risk_label_to_int");
    ASSERT_EQ_INT(zp_risk_label_to_int("CRITICAL"), 4);
    ASSERT_EQ_INT(zp_risk_label_to_int("HIGH"), 3);
    ASSERT_EQ_INT(zp_risk_label_to_int("MEDIUM"), 2);
    ASSERT_EQ_INT(zp_risk_label_to_int("LOW"), 1);
    ASSERT_EQ_INT(zp_risk_label_to_int("INFO"), 0);
    ASSERT_EQ_INT(zp_risk_label_to_int(NULL), 0);
    ASSERT_EQ_INT(zp_risk_label_to_int("nonsense"), 0);
    ZP_TEST_END("risk_label_to_int", 1);
    return ZP_TEST_PASS;
}

int test_risk_finding_clamp(void)
{
    ZP_TEST_BEGIN("risk_finding_clamp");
    float high = zp_risk_finding(ZP_SEV_CRITICAL, 5.0f);
    ASSERT_TRUE(high <= 10.0f);
    float low = zp_risk_finding(ZP_SEV_INFO, -1.0f);
    ASSERT_TRUE(low >= 0.0f);
    ZP_TEST_END("risk_finding_clamp", 1);
    return ZP_TEST_PASS;
}
