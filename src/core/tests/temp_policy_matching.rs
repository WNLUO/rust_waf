use super::*;

use crate::core::ai_temp_policy::match_ai_temp_policy;

fn test_policy(scope_type: &str, scope_value: &str, operator: &str) -> AiTempPolicyEntry {
    AiTempPolicyEntry {
        id: 1,
        created_at: 0,
        updated_at: 0,
        expires_at: i64::MAX,
        status: "active".to_string(),
        source_report_id: None,
        policy_key: "test".to_string(),
        title: "test".to_string(),
        policy_type: "test".to_string(),
        layer: "l7".to_string(),
        scope_type: scope_type.to_string(),
        scope_value: scope_value.to_string(),
        action: "increase_challenge".to_string(),
        operator: operator.to_string(),
        suggested_value: "80".to_string(),
        rationale: "test".to_string(),
        confidence: 80,
        auto_applied: true,
        hit_count: 0,
        last_hit_at: None,
        effect_json: "{}".to_string(),
    }
}

#[test]
fn test_route_prefix_temp_policy_matching() {
    let matched = match_ai_temp_policy(
        &test_policy("route", "/login/*", "prefix"),
        "example.com",
        "/login/submit",
        "203.0.113.8",
        Some("fp:abc"),
    )
    .unwrap();
    assert_eq!(matched.match_mode, "prefix");
    assert_eq!(matched.matched_value, "/login/submit");
}

#[test]
fn test_host_suffix_temp_policy_matching() {
    let matched = match_ai_temp_policy(
        &test_policy("host", "*.example.com", "suffix"),
        "api.example.com",
        "/",
        "203.0.113.8",
        Some("fp:abc"),
    )
    .unwrap();
    assert_eq!(matched.match_mode, "suffix");
}

#[test]
fn test_source_ip_cidr_temp_policy_matching() {
    let matched = match_ai_temp_policy(
        &test_policy("source_ip", "203.0.113.0/24", "cidr"),
        "example.com",
        "/",
        "203.0.113.77",
        Some("fp:abc"),
    )
    .unwrap();
    assert_eq!(matched.match_mode, "cidr");
}
