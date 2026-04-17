use super::*;

#[tokio::test]
async fn test_sqlite_store_seeds_and_loads_rules() {
    let path = unique_test_db_path("rules");
    let store = SqliteStore::new(path, true).await.unwrap();
    let rules = vec![
        Rule {
            id: "rule-1".to_string(),
            name: "Block SQLi".to_string(),
            enabled: true,
            layer: RuleLayer::L7,
            pattern: "(?i)union\\s+select".to_string(),
            action: RuleAction::Block,
            severity: Severity::High,
            plugin_template_id: None,
            response_template: None,
        },
        Rule {
            id: "rule-2".to_string(),
            name: "Alert Port Scan".to_string(),
            enabled: true,
            layer: RuleLayer::L4,
            pattern: "scan".to_string(),
            action: RuleAction::Alert,
            severity: Severity::Medium,
            plugin_template_id: None,
            response_template: None,
        },
    ];

    let inserted = store.seed_rules(&rules).await.unwrap();
    assert_eq!(inserted, 2);

    let inserted_again = store.seed_rules(&rules).await.unwrap();
    assert_eq!(inserted_again, 0);

    let loaded_rules = store.load_rules().await.unwrap();
    assert_eq!(loaded_rules.len(), 2);
    assert_eq!(loaded_rules[0].id, "rule-1");
    assert_eq!(loaded_rules[1].id, "rule-2");
    assert_eq!(
        store.load_rule("rule-1").await.unwrap().unwrap().name,
        "Block SQLi"
    );

    let updated_rule = Rule {
        id: "rule-1".to_string(),
        name: "Block Updated SQLi".to_string(),
        enabled: false,
        layer: RuleLayer::L7,
        pattern: "(?i)select".to_string(),
        action: RuleAction::Alert,
        severity: Severity::Critical,
        plugin_template_id: None,
        response_template: None,
    };
    store.upsert_rule(&updated_rule).await.unwrap();
    let fetched_updated = store.load_rule("rule-1").await.unwrap().unwrap();
    assert_eq!(fetched_updated.name, "Block Updated SQLi");
    assert!(!fetched_updated.enabled);
    assert_eq!(fetched_updated.action, RuleAction::Alert);
    assert_eq!(fetched_updated.severity, Severity::Critical);

    let inserted_new = store
        .insert_rule(&Rule {
            id: "rule-3".to_string(),
            name: "New Rule".to_string(),
            enabled: true,
            layer: RuleLayer::L4,
            pattern: "syn".to_string(),
            action: RuleAction::Block,
            severity: Severity::Low,
            plugin_template_id: None,
            response_template: None,
        })
        .await
        .unwrap();
    assert!(inserted_new);
    let inserted_duplicate = store.insert_rule(&updated_rule).await.unwrap();
    assert!(!inserted_duplicate);

    let deleted = store.delete_rule("rule-2").await.unwrap();
    assert!(deleted);
    let deleted_missing = store.delete_rule("missing").await.unwrap();
    assert!(!deleted_missing);

    let latest_version = store.latest_rules_version().await.unwrap();
    assert!(latest_version > 0);

    let summary = store.metrics_summary().await.unwrap();
    assert_eq!(summary.rules, 2);
    assert!(summary.latest_rule_update_at.is_some());
}

#[tokio::test]
async fn test_sqlite_store_seeds_and_updates_app_config() {
    let path = unique_test_db_path("app_config");
    let store = SqliteStore::new(path, true).await.unwrap();
    let initial = Config {
        runtime_profile: RuntimeProfile::Standard,
        api_enabled: true,
        sqlite_enabled: true,
        sqlite_path: "data/custom.db".to_string(),
        max_concurrent_tasks: 321,
        ..Config::default()
    };

    let inserted = store.seed_app_config(&initial).await.unwrap();
    assert!(inserted);

    let loaded = store.load_app_config().await.unwrap().unwrap();
    assert!(loaded.api_enabled);
    assert_eq!(loaded.sqlite_path, "data/custom.db");

    let inserted_again = store.seed_app_config(&Config::default()).await.unwrap();
    assert!(!inserted_again);

    let updated = Config {
        api_enabled: false,
        max_concurrent_tasks: 654,
        ..initial.clone()
    };
    store.upsert_app_config(&updated).await.unwrap();

    let loaded_updated = store.load_app_config().await.unwrap().unwrap();
    assert!(!loaded_updated.api_enabled);
    assert_eq!(loaded_updated.max_concurrent_tasks, 654);
}

#[tokio::test]
async fn test_sqlite_store_loads_legacy_app_config_with_default_safeline() {
    let path = unique_test_db_path("legacy_app_config");
    let store = SqliteStore::new(path, true).await.unwrap();

    sqlx::query(
        r#"
            INSERT INTO app_config (id, config_json, updated_at)
            VALUES (?, ?, ?)
            "#,
    )
    .bind(1_i64)
    .bind(r#"{"interface":"eth0","listen_addrs":["0.0.0.0:8080"],"runtime_profile":"minimal","api_enabled":false,"api_bind":"127.0.0.1:3740","bloom_enabled":false,"l4_bloom_false_positive_verification":false,"l7_bloom_false_positive_verification":false,"maintenance_interval_secs":60,"l4_config":{"ddos_protection_enabled":true,"advanced_ddos_enabled":false,"connection_rate_limit":64,"syn_flood_threshold":32,"max_tracked_ips":512,"max_blocked_ips":128,"state_ttl_secs":180,"bloom_filter_scale":1.0},"l7_config":{"http_inspection_enabled":true,"max_request_size":4096,"http2_config":{"enabled":false,"max_concurrent_streams":50,"max_frame_size":16384,"enable_priorities":true,"initial_window_size":65535},"bloom_filter_scale":1.0},"http3_config":{"enabled":false,"listen_addr":"0.0.0.0:8443","max_concurrent_streams":50,"idle_timeout_secs":60,"mtu":1200,"max_frame_size":65536,"enable_connection_migration":false,"qpack_table_size":2048,"certificate_path":null,"private_key_path":null,"enable_tls13":true},"rules":[],"metrics_enabled":true,"sqlite_enabled":true,"sqlite_path":"data/waf.db","sqlite_auto_migrate":true,"sqlite_rules_enabled":false,"max_concurrent_tasks":128}"#)
    .bind(unix_timestamp())
    .execute(&store.pool)
    .await
    .unwrap();

    let loaded = store.load_app_config().await.unwrap().unwrap();
    assert!(loaded.integrations.safeline.enabled);
    assert_eq!(
        loaded.integrations.safeline.auth_probe_path,
        "/api/open/system/key"
    );
    assert_eq!(loaded.console_settings.gateway_name, "玄枢防护网关");
}
