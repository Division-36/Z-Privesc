struct test_case;

#ifndef Z_PRIVESC_TEST_CASES_INC
#define Z_PRIVESC_TEST_CASES_INC

#include "test_main.h"

static const struct test_case TESTS[] = {
    {"truthimatics_empty_chain",         test_truthimatics_empty_chain},
    {"truthimatics_single_deterministic",test_truthimatics_single_deterministic},
    {"truthimatics_majority_reject",     test_truthimatics_majority_reject},
    {"truthimatics_dominant_link",       test_truthimatics_dominant_link},
    {"truthimatics_uncertain_wins",      test_truthimatics_uncertain_wins},
    {"truthimatics_weight_clamp",        test_truthimatics_weight_clamp},
    {"truthimatics_release_releases",    test_truthimatics_release_releases},
    {"verdict_strings",                  test_verdict_strings},
    {"severity_strings",                 test_severity_strings},

    {"risk_finding_range",               test_risk_finding_range},
    {"risk_probe_empty",                 test_risk_probe_empty},
    {"risk_probe_worst_dominates",       test_risk_probe_worst_dominates},
    {"risk_overall_bonus",               test_risk_overall_bonus},
    {"risk_overall_empty",               test_risk_overall_empty},
    {"risk_label_bands",                 test_risk_label_bands},
    {"risk_label_to_int",                test_risk_label_to_int},
    {"risk_finding_clamp",               test_risk_finding_clamp},

    {"suid_finds_fake_suid",             test_suid_finds_fake_suid},
    {"suid_ignores_symlink",             test_suid_ignores_symlink},
    {"suid_empty_root",                  test_suid_empty_root},
    {"suid_dangerous_basename",          test_suid_dangerous_basename},

    {"writable_path_detects_dot",        test_writable_path_detects_dot},
    {"writable_path_detects_world_writable",
                                         test_writable_path_detects_world_writable},
    {"writable_path_handles_missing",    test_writable_path_handles_missing},
    {"writable_path_uses_tempdir",       test_writable_path_uses_tempdir},

    {"capabilities_safe_chain",          test_capabilities_safe_chain},
    {"capabilities_proc_status",         test_capabilities_proc_status},
    {"capabilities_critical_filter",     test_capabilities_critical_filter},

    {"writable_etc_clean",               test_writable_etc_clean},
    {"writable_etc_detects_writable_file",
                                         test_writable_etc_detects_writable_file},
    {"writable_etc_detects_writable_dir",test_writable_etc_detects_writable_dir},

    {"docker_socket_missing",            test_docker_socket_missing},
    {"docker_socket_handles_no_socket",  test_docker_socket_handles_no_socket},

    {"polkit_missing_pieces",            test_polkit_missing_pieces},
    {"polkit_old_version_match",         test_polkit_old_version_match},

    {"world_writable_clean",             test_world_writable_clean},
    {"world_writable_sticky_bit",        test_world_writable_sticky_bit},

    {"kernel_vuln_old_kernel",           test_kernel_vuln_old_kernel},
    {"kernel_vuln_new_kernel",           test_kernel_vuln_new_kernel},
    {"kernel_vuln_handles_garbage",      test_kernel_vuln_handles_garbage},

    {"audit_emits_json",                 test_audit_emits_json},
    {"audit_emits_html",                 test_audit_emits_html},
    {"audit_add_finding_resize",         test_audit_add_finding_resize},

    {"util_path_join",                   test_util_path_join},
    {"util_path_normalize",              test_util_path_normalize},
    {"util_hex_encode",                  test_util_hex_encode},

    // Edge case and hard tests
    {"util_path_extreme_length",         test_util_path_extreme_length},
    {"util_null_empty_inputs",           test_util_null_empty_inputs},
    {"audit_massive_findings",           test_audit_massive_findings},
    {"audit_zero_allocations",           test_audit_zero_allocations},
    {"evidence_massive_chain",           test_evidence_massive_chain},
    {"truthimatics_extreme_weights",     test_truthimatics_extreme_weights},
    {"risk_boundary_values",             test_risk_boundary_values},
    {"file_permission_denied",           test_file_permission_denied},
    {"deep_directory_structure",         test_deep_directory_structure},
    {"special_characters_paths",         test_special_characters_paths},
    {"audit_memory_leak_fix",            test_audit_memory_leak_fix},
    {"capabilities_long_paths",          test_capabilities_long_paths},
    {"string_truncation_safety",         test_string_truncation_safety},
    {"capabilities_edge_cases",          test_capabilities_edge_cases}
};

#endif
