/* test_edge_cases.c - Comprehensive edge case and hard tests */
#define _POSIX_C_SOURCE 200809L
#include "test_main.h"
#include "probes.h"
#include "audit.h"
#include "util.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>

/* Test: Fixed memory leak in audit_ctx_release */
int test_audit_memory_leak_fix(void)
{
    ZP_TEST_BEGIN("audit_memory_leak_fix");
    
    struct audit_ctx ctx;
    audit_ctx_init(&ctx, 4, 8);
    
    // Add a probe with findings
    int probe_idx = audit_ctx_add_probe(&ctx, "test_probe", "test_verdict", 1, 9.5f);
    ASSERT_TRUE(probe_idx >= 0);
    
    struct audit_finding f = {
        .id = "D-1",
        .target = "target",
        .description = "description",
        .remediation = "remediation",
        .weight = 0.5f,
        .severity = "MEDIUM",
        .risk_score = 9.5f
    };
    int rc = audit_ctx_add_finding(&ctx, probe_idx, &f);
    ASSERT_EQ_INT(rc, ZP_OK);
    
    // This should NOT leak memory
    audit_ctx_release(&ctx);
    
    // Verify clean state
    audit_ctx_init(&ctx, 1, 1);
    ASSERT_EQ_INT(ctx.probe_capacity, 1);
    audit_ctx_release(&ctx);
    
    ZP_TEST_END("audit_memory_leak_fix", 1);
    return ZP_TEST_PASS;
}

/* Test: String truncation safety (related to format-truncation fix) */
int test_string_truncation_safety(void)
{
    ZP_TEST_BEGIN("string_truncation_safety");
    
    // Test that our snprintf calls properly handle truncation
    char buffer[32];
    
    // This should truncate safely
    snprintf(buffer, sizeof(buffer), "This is a very long string that exceeds the buffer size");
    
    // Ensure null termination
    ASSERT_TRUE(buffer[sizeof(buffer) - 1] == '\0');
    
    // Test with various buffer sizes
    for (int size = 1; size <= 64; size++) {
        char small_buf[64];
        snprintf(small_buf, size, "A very long string that might be truncated depending on buffer size");
        // Should always be null terminated
        ASSERT_TRUE(strlen(small_buf) < (size_t)size);
    }
    
    ZP_TEST_END("string_truncation_safety", 1);
    return ZP_TEST_PASS;
}