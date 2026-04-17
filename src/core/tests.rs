use super::*;
use crate::config::{
    Config, Http3Config, L4Config, L7Config, Rule, RuleAction, RuleLayer, RuntimeProfile, Severity,
};
use crate::core::ai_temp_policy::match_ai_temp_policy;
use std::time::{SystemTime, UNIX_EPOCH};

fn unique_test_db_path(name: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    std::env::temp_dir()
        .join(format!(
            "{}_core_{}_{}.db",
            env!("CARGO_PKG_NAME"),
            name,
            nanos
        ))
        .display()
        .to_string()
}

fn test_rule(id: &str, pattern: &str) -> Rule {
    Rule {
        id: id.to_string(),
        name: format!("Rule {}", id),
        enabled: true,
        layer: RuleLayer::L7,
        pattern: pattern.to_string(),
        action: RuleAction::Block,
        severity: Severity::High,
        plugin_template_id: None,
        response_template: None,
    }
}

#[tokio::test]
async fn test_context_loads_and_refreshes_sqlite_rules() {
    let db_path = unique_test_db_path("rules_refresh");
    let config = Config {
        interface: "lo0".to_string(),
        listen_addrs: vec!["127.0.0.1:0".to_string()],
        tcp_upstream_addr: None,
        udp_upstream_addr: None,
        runtime_profile: RuntimeProfile::Standard,
        api_enabled: false,
        api_bind: "127.0.0.1:3740".to_string(),
        bloom_enabled: false,
        l4_bloom_false_positive_verification: false,
        l7_bloom_false_positive_verification: false,
        maintenance_interval_secs: 30,
        l4_config: L4Config::default(),
        l7_config: L7Config::default(),
        http3_config: Http3Config::default(),
        rules: vec![test_rule("seed-1", "attack")],
        metrics_enabled: true,
        sqlite_enabled: true,
        sqlite_path: db_path,
        sqlite_auto_migrate: true,
        sqlite_rules_enabled: true,
        max_concurrent_tasks: 128,
        ..Config::default()
    };

    let context = WafContext::new(config).await.unwrap();
    assert_eq!(context.active_rule_count(), 1);

    let store = context.sqlite_store.as_ref().unwrap();
    store
        .seed_rules(&[test_rule("seed-2", "exploit")])
        .await
        .unwrap();

    let refreshed = context.refresh_rules_from_storage().await.unwrap();
    assert!(refreshed);
    assert_eq!(context.active_rule_count(), 2);
}

#[tokio::test]
async fn test_context_restores_active_local_blocked_ips_into_runtime_memory() {
    let db_path = unique_test_db_path("blocked_ip_restore");
    let bootstrap_store = SqliteStore::new(db_path.clone(), true).await.unwrap();
    let now = unix_timestamp();
    bootstrap_store.enqueue_blocked_ip(crate::storage::BlockedIpRecord::new(
        "203.0.113.10",
        "restore me",
        now,
        now + 120,
    ));
    bootstrap_store.enqueue_blocked_ip(crate::storage::BlockedIpRecord::new(
        "203.0.113.11",
        "already expired",
        now - 120,
        now - 1,
    ));
    bootstrap_store.flush().await.unwrap();
    bootstrap_store.shutdown().await.unwrap();

    let config = Config {
        interface: "lo0".to_string(),
        listen_addrs: vec!["127.0.0.1:0".to_string()],
        tcp_upstream_addr: None,
        udp_upstream_addr: None,
        runtime_profile: RuntimeProfile::Standard,
        api_enabled: false,
        api_bind: "127.0.0.1:3740".to_string(),
        bloom_enabled: false,
        l4_bloom_false_positive_verification: false,
        l7_bloom_false_positive_verification: false,
        maintenance_interval_secs: 30,
        l4_config: L4Config {
            connection_rate_limit: 1,
            ..L4Config::default()
        },
        l7_config: L7Config::default(),
        http3_config: Http3Config::default(),
        metrics_enabled: true,
        sqlite_enabled: true,
        sqlite_path: db_path,
        sqlite_auto_migrate: true,
        sqlite_rules_enabled: true,
        max_concurrent_tasks: 128,
        ..Config::default()
    };

    let context = WafContext::new(config).await.unwrap();
    let stats = context
        .l4_inspector()
        .expect("l4 inspector should be available")
        .get_statistics();
    assert_eq!(stats.connections.blocked_connections, 1);
}

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
