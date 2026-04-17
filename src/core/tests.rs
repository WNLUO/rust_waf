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

#[tokio::test]
async fn test_ai_auto_defense_applies_hot_route_temp_policy() {
    let db_path = unique_test_db_path("ai_auto_defense");
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
        sqlite_enabled: true,
        sqlite_path: db_path,
        sqlite_auto_migrate: true,
        sqlite_rules_enabled: false,
        max_concurrent_tasks: 128,
        ..Config::default()
    };
    let context = WafContext::new(config).await.unwrap();
    let result = InspectionResult::drop(InspectionLayer::L7, "route pressure");

    for _ in 0..5 {
        let mut request = crate::protocol::UnifiedHttpRequest::new(
            crate::protocol::HttpVersion::Http1_1,
            "POST".to_string(),
            "/api/login".to_string(),
        );
        request.add_metadata("gateway.site_id".to_string(), "site-a".to_string());
        context.note_site_defense_signal(&request, &result);
    }

    let now = unix_timestamp();
    let trigger_reason = context.consume_ai_auto_defense_trigger(now);
    assert!(trigger_reason
        .as_deref()
        .is_some_and(|reason| reason.starts_with("route_pressure:site-a:/api/login")));
    let run = context
        .run_ai_auto_defense(now, trigger_reason)
        .await
        .unwrap();

    assert_eq!(run.applied, 1);
    let active = context.active_ai_temp_policies();
    assert_eq!(active.len(), 1);
    let policy = &active[0];
    assert_eq!(policy.action, "tighten_route_cc");
    assert_eq!(policy.scope_type, "route");
    assert_eq!(policy.scope_value, "/api/login");
    assert_eq!(policy.operator, "exact");
    assert_eq!(policy.suggested_value, "45");
    assert!(policy.auto_applied);
}

#[tokio::test]
async fn test_ai_route_profile_refreshes_into_auto_defense_snapshot() {
    let db_path = unique_test_db_path("ai_route_profile");
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
        sqlite_enabled: true,
        sqlite_path: db_path,
        sqlite_auto_migrate: true,
        sqlite_rules_enabled: false,
        max_concurrent_tasks: 128,
        ..Config::default()
    };
    let context = WafContext::new(config).await.unwrap();
    let store = context.sqlite_store.as_ref().unwrap();
    store
        .upsert_ai_route_profile(&crate::storage::AiRouteProfileUpsert {
            site_id: "site-a".to_string(),
            route_pattern: "/api/login".to_string(),
            match_mode: "exact".to_string(),
            route_type: "authentication".to_string(),
            sensitivity: "high".to_string(),
            auth_required: "false".to_string(),
            normal_traffic_pattern: "interactive".to_string(),
            recommended_actions: vec![
                "increase_challenge".to_string(),
                "tighten_route_cc".to_string(),
            ],
            avoid_actions: vec!["add_temp_block".to_string()],
            evidence_json: serde_json::json!({
                "source": "test",
                "reason": "login semantics"
            })
            .to_string(),
            confidence: 88,
            source: "ai_observed".to_string(),
            status: "active".to_string(),
            rationale: "AI inferred login semantics".to_string(),
            last_observed_at: Some(unix_timestamp()),
            reviewed_at: None,
        })
        .await
        .unwrap();

    context.refresh_ai_route_profiles().await.unwrap();
    let snapshot = context
        .ai_defense_signal_snapshot(unix_timestamp(), Some("test".to_string()))
        .await
        .unwrap();

    assert_eq!(snapshot.route_profiles.len(), 1);
    let profile = &snapshot.route_profiles[0];
    assert_eq!(profile.site_id, "site-a");
    assert_eq!(profile.route_pattern, "/api/login");
    assert_eq!(profile.route_type, "authentication");
    assert!(profile
        .recommended_actions
        .iter()
        .any(|item| item == "tighten_route_cc"));
}

#[tokio::test]
async fn test_ai_route_profile_status_controls_runtime_cache() {
    let db_path = unique_test_db_path("ai_route_profile_status");
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
        sqlite_enabled: true,
        sqlite_path: db_path,
        sqlite_auto_migrate: true,
        sqlite_rules_enabled: false,
        max_concurrent_tasks: 128,
        ..Config::default()
    };
    let context = WafContext::new(config).await.unwrap();
    let store = context.sqlite_store.as_ref().unwrap();
    store
        .upsert_ai_route_profile(&crate::storage::AiRouteProfileUpsert {
            site_id: "site-a".to_string(),
            route_pattern: "/api/login".to_string(),
            match_mode: "exact".to_string(),
            route_type: "authentication".to_string(),
            sensitivity: "high".to_string(),
            auth_required: "false".to_string(),
            normal_traffic_pattern: "interactive".to_string(),
            recommended_actions: vec!["tighten_route_cc".to_string()],
            avoid_actions: Vec::new(),
            evidence_json: "{}".to_string(),
            confidence: 88,
            source: "ai_observed".to_string(),
            status: "candidate".to_string(),
            rationale: "candidate".to_string(),
            last_observed_at: Some(unix_timestamp()),
            reviewed_at: None,
        })
        .await
        .unwrap();

    context.refresh_ai_route_profiles().await.unwrap();
    assert!(context.active_ai_route_profiles().is_empty());

    let candidate = store
        .list_ai_route_profiles(Some("site-a"), Some("candidate"), 10)
        .await
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    store
        .update_ai_route_profile_status(candidate.id, "active", Some(unix_timestamp()))
        .await
        .unwrap();
    context.refresh_ai_route_profiles().await.unwrap();

    assert_eq!(context.active_ai_route_profiles().len(), 1);
}

#[tokio::test]
async fn test_ai_auto_defense_generates_route_profile_candidate() {
    let db_path = unique_test_db_path("ai_route_profile_candidate");
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
        sqlite_enabled: true,
        sqlite_path: db_path,
        sqlite_auto_migrate: true,
        sqlite_rules_enabled: false,
        max_concurrent_tasks: 128,
        ..Config::default()
    };
    let context = WafContext::new(config).await.unwrap();
    let result = InspectionResult::drop(InspectionLayer::L7, "route pressure");

    for idx in 0..5 {
        let mut request = crate::protocol::UnifiedHttpRequest::new(
            crate::protocol::HttpVersion::Http1_1,
            "POST".to_string(),
            "/api/login".to_string(),
        );
        request.set_client_ip(format!("203.0.113.{}", idx + 10));
        request.add_metadata("gateway.site_id".to_string(), "site-a".to_string());
        context.note_site_defense_signal(&request, &result);
        context.note_ai_route_result(
            &request,
            AiRouteResultObservation {
                status_code: 429,
                latency_ms: Some(20),
                upstream_error: false,
                local_response: true,
                blocked: true,
            },
        );
    }

    let now = unix_timestamp();
    let trigger_reason = context.consume_ai_auto_defense_trigger(now);
    context
        .run_ai_auto_defense(now, trigger_reason)
        .await
        .unwrap();

    let profiles = context
        .sqlite_store
        .as_ref()
        .unwrap()
        .list_ai_route_profiles(Some("site-a"), Some("candidate"), 20)
        .await
        .unwrap();

    assert_eq!(profiles.len(), 1);
    let profile = &profiles[0];
    assert_eq!(profile.route_pattern, "/api/login");
    assert_eq!(profile.route_type, "authentication");
    assert_eq!(profile.status, "candidate");
    assert_eq!(profile.source, "local_ai_observed");
    let evidence: serde_json::Value = serde_json::from_str(&profile.evidence_json).unwrap();
    assert_eq!(evidence["learning_mode"], "observed_candidate");
    assert_eq!(evidence["route_pressure"]["total_events"], 5);
    assert_eq!(evidence["identity"]["distinct_client_count"], 5);
    assert_eq!(evidence["route_effect"]["total_responses"], 5);
    assert_eq!(evidence["route_effect"]["status_families"]["4xx"], 5);
}

#[tokio::test]
async fn test_ai_auto_defense_can_relearn_rejected_route_profile() {
    let db_path = unique_test_db_path("ai_route_profile_relearn");
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
        sqlite_enabled: true,
        sqlite_path: db_path,
        sqlite_auto_migrate: true,
        sqlite_rules_enabled: false,
        max_concurrent_tasks: 128,
        ..Config::default()
    };
    let context = WafContext::new(config).await.unwrap();
    let store = context.sqlite_store.as_ref().unwrap();
    store
        .upsert_ai_route_profile(&crate::storage::AiRouteProfileUpsert {
            site_id: "site-a".to_string(),
            route_pattern: "/api/login".to_string(),
            match_mode: "exact".to_string(),
            route_type: "unknown".to_string(),
            sensitivity: "unknown".to_string(),
            auth_required: "unknown".to_string(),
            normal_traffic_pattern: "unknown".to_string(),
            recommended_actions: Vec::new(),
            avoid_actions: Vec::new(),
            evidence_json: "{}".to_string(),
            confidence: 20,
            source: "ai_observed".to_string(),
            status: "rejected".to_string(),
            rationale: "old rejected candidate".to_string(),
            last_observed_at: Some(unix_timestamp()),
            reviewed_at: Some(unix_timestamp()),
        })
        .await
        .unwrap();

    let result = InspectionResult::drop(InspectionLayer::L7, "route pressure");
    for idx in 0..5 {
        let mut request = crate::protocol::UnifiedHttpRequest::new(
            crate::protocol::HttpVersion::Http1_1,
            "POST".to_string(),
            "/api/login".to_string(),
        );
        request.set_client_ip(format!("203.0.113.{}", idx + 40));
        request.add_metadata("gateway.site_id".to_string(), "site-a".to_string());
        context.note_site_defense_signal(&request, &result);
    }

    let now = unix_timestamp();
    let trigger_reason = context.consume_ai_auto_defense_trigger(now);
    context
        .run_ai_auto_defense(now, trigger_reason)
        .await
        .unwrap();

    let profiles = store
        .list_ai_route_profiles(Some("site-a"), Some("candidate"), 20)
        .await
        .unwrap();

    assert_eq!(profiles.len(), 1);
    let profile = &profiles[0];
    assert_eq!(profile.source, "local_ai_relearned");
    let evidence: serde_json::Value = serde_json::from_str(&profile.evidence_json).unwrap();
    assert_eq!(evidence["learning_mode"], "relearn_after_rejected");
}

#[tokio::test]
async fn test_ai_defense_snapshot_includes_route_effect_feedback() {
    let context = WafContext::new(Config {
        sqlite_enabled: false,
        ..Config::default()
    })
    .await
    .unwrap();

    for idx in 0..5 {
        let mut request = crate::protocol::UnifiedHttpRequest::new(
            crate::protocol::HttpVersion::Http1_1,
            "GET".to_string(),
            "/api/login".to_string(),
        );
        request.set_client_ip(format!("203.0.113.{}", idx + 70));
        request.add_metadata("gateway.site_id".to_string(), "site-a".to_string());
        request.add_metadata("ai.policy.matched_ids".to_string(), "42".to_string());
        request.add_metadata(
            "ai.policy.matched_actions".to_string(),
            "increase_challenge".to_string(),
        );
        request.add_metadata("l7.cc.challenge_verified".to_string(), "true".to_string());
        context.note_ai_route_result(
            &request,
            AiRouteResultObservation {
                status_code: 429,
                latency_ms: Some(25),
                upstream_error: false,
                local_response: true,
                blocked: true,
            },
        );
    }

    let snapshot = context
        .ai_defense_signal_snapshot(unix_timestamp(), Some("test".to_string()))
        .await
        .unwrap();
    let effect = snapshot
        .route_effects
        .iter()
        .find(|item| item.site_id == "site-a" && item.route == "/api/login")
        .expect("route effect should be present");

    assert_eq!(effect.total_responses, 5);
    assert_eq!(effect.policy_matched_responses, 5);
    assert_eq!(effect.challenge_verified, 5);
    assert_eq!(effect.false_positive_risk, "high");
}

#[tokio::test]
async fn test_visitor_intelligence_trusts_verified_browser_session() {
    let context = WafContext::new(Config {
        sqlite_enabled: false,
        ..Config::default()
    })
    .await
    .unwrap();

    for uri in [
        "/",
        "/assets/app.css",
        "/assets/app.js",
        "/assets/logo.png",
        "/about",
        "/assets/site.woff2",
    ] {
        let mut request = crate::protocol::UnifiedHttpRequest::new(
            crate::protocol::HttpVersion::Http1_1,
            "GET".to_string(),
            uri.to_string(),
        );
        request.set_client_ip("203.0.113.210".to_string());
        request.add_header("host".to_string(), "example.test".to_string());
        request.add_header(
            "user-agent".to_string(),
            "Mozilla/5.0 visitor intelligence test".to_string(),
        );
        request.add_header("referer".to_string(), "https://example.test/".to_string());
        request.add_header("cookie".to_string(), "rwaf_fp=verified-browser".to_string());
        request.add_metadata("gateway.site_id".to_string(), "site-a".to_string());
        context.note_ai_route_result(
            &request,
            AiRouteResultObservation {
                status_code: 200,
                latency_ms: Some(18),
                upstream_error: false,
                local_response: false,
                blocked: false,
            },
        );
    }

    let snapshot = context.visitor_intelligence_snapshot(10);
    let profile = snapshot
        .profiles
        .iter()
        .find(|item| item.identity_key == "fp:verified-browser")
        .expect("verified browser visitor should be tracked");
    assert_eq!(profile.state, "trusted_session");
    assert!(profile.human_confidence >= 75);
    assert!(snapshot
        .recommendations
        .iter()
        .any(|item| item.action == "mark_trusted_temporarily"));
}

#[tokio::test]
async fn test_visitor_intelligence_triggers_ai_after_suspicious_volume() {
    let context = WafContext::new(Config {
        sqlite_enabled: false,
        ..Config::default()
    })
    .await
    .unwrap();

    for _ in 0..8 {
        let mut request = crate::protocol::UnifiedHttpRequest::new(
            crate::protocol::HttpVersion::Http1_1,
            "GET".to_string(),
            "/wp-login.php".to_string(),
        );
        request.set_client_ip("203.0.113.211".to_string());
        request.add_header("host".to_string(), "example.test".to_string());
        request.add_header("user-agent".to_string(), "curl/8.0".to_string());
        request.add_metadata("gateway.site_id".to_string(), "site-a".to_string());
        context.note_ai_route_result(
            &request,
            AiRouteResultObservation {
                status_code: 404,
                latency_ms: Some(12),
                upstream_error: false,
                local_response: false,
                blocked: false,
            },
        );
    }

    let snapshot = context.visitor_intelligence_snapshot(10);
    let profile = snapshot
        .profiles
        .iter()
        .find(|item| item.client_ip == "203.0.113.211")
        .expect("suspicious visitor should be tracked");
    assert_eq!(profile.state, "suspected_probe");
    assert_eq!(profile.tracking_priority, "high");
    assert!(snapshot
        .recommendations
        .iter()
        .any(|item| item.action == "increase_challenge"));

    let trigger = context.consume_ai_auto_defense_trigger(unix_timestamp());
    assert!(trigger
        .as_deref()
        .is_some_and(|reason| reason.starts_with("visitor_intelligence:increase_challenge")));
}

#[tokio::test]
async fn test_visitor_intelligence_uses_ai_route_profile_business_semantics() {
    let db_path = unique_test_db_path("visitor_ai_route_semantics");
    let context = WafContext::new(Config {
        sqlite_enabled: true,
        sqlite_path: db_path,
        sqlite_auto_migrate: true,
        ..Config::default()
    })
    .await
    .unwrap();
    context
        .sqlite_store
        .as_ref()
        .unwrap()
        .upsert_ai_route_profile(&crate::storage::AiRouteProfileUpsert {
            site_id: "site-a".to_string(),
            route_pattern: "/secure".to_string(),
            match_mode: "prefix".to_string(),
            route_type: "admin".to_string(),
            sensitivity: "high".to_string(),
            auth_required: "true".to_string(),
            normal_traffic_pattern: "authenticated users only".to_string(),
            recommended_actions: vec!["increase_challenge".to_string()],
            avoid_actions: vec!["temp_block_ip".to_string()],
            evidence_json: "{}".to_string(),
            confidence: 91,
            source: "ai_observed".to_string(),
            status: "active".to_string(),
            rationale: "AI labeled protected admin area".to_string(),
            last_observed_at: Some(unix_timestamp()),
            reviewed_at: Some(unix_timestamp()),
        })
        .await
        .unwrap();
    context.refresh_ai_route_profiles().await.unwrap();

    for status_code in [403, 403, 200] {
        let mut request = crate::protocol::UnifiedHttpRequest::new(
            crate::protocol::HttpVersion::Http1_1,
            "GET".to_string(),
            "/secure/panel".to_string(),
        );
        request.set_client_ip("203.0.113.212".to_string());
        request.add_header("host".to_string(), "example.test".to_string());
        request.add_header("user-agent".to_string(), "Mozilla/5.0".to_string());
        request.add_metadata("gateway.site_id".to_string(), "site-a".to_string());
        context.note_ai_route_result(
            &request,
            AiRouteResultObservation {
                status_code,
                latency_ms: Some(22),
                upstream_error: false,
                local_response: false,
                blocked: false,
            },
        );
    }

    let snapshot = context.visitor_intelligence_snapshot(10);
    let profile = snapshot
        .profiles
        .iter()
        .find(|item| item.client_ip == "203.0.113.212")
        .expect("visitor should be tracked");
    assert_eq!(profile.business_route_types.get("admin"), Some(&3));
    assert_eq!(profile.auth_required_route_count, 3);
    assert_eq!(profile.auth_rejected_count, 2);
    assert_eq!(profile.auth_success_count, 1);
}

#[tokio::test]
async fn test_visitor_intelligence_records_challenge_js_telemetry() {
    let context = WafContext::new(Config {
        sqlite_enabled: false,
        ..Config::default()
    })
    .await
    .unwrap();
    let mut request = crate::protocol::UnifiedHttpRequest::new(
        crate::protocol::HttpVersion::Http1_1,
        "POST".to_string(),
        "/.well-known/waf/browser-fingerprint-report".to_string(),
    );
    request.set_client_ip("203.0.113.213".to_string());
    request.add_header("user-agent".to_string(), "Mozilla/5.0".to_string());
    request.add_metadata("gateway.site_id".to_string(), "site-a".to_string());
    let payload = serde_json::json!({
        "fingerprintId": "challenge-js-browser",
        "challenge": {
            "rendered": true,
            "js": true,
            "waitMs": 2800
        }
    });

    context.note_visitor_fingerprint_report(&request, "challenge-js-browser", Some(&payload));

    let snapshot = context.visitor_intelligence_snapshot(10);
    let profile = snapshot
        .profiles
        .iter()
        .find(|item| item.identity_key == "fp:challenge-js-browser")
        .expect("challenge js visitor should be tracked");
    assert_eq!(profile.challenge_page_report_count, 1);
    assert_eq!(profile.challenge_js_report_count, 1);
    assert!(profile
        .flags
        .iter()
        .any(|flag| flag == "challenge_js_report_seen"));
}

#[tokio::test]
async fn test_ai_defense_snapshot_includes_policy_effect_feedback() {
    let db_path = unique_test_db_path("ai_policy_effect_snapshot");
    let context = WafContext::new(Config {
        sqlite_enabled: true,
        sqlite_path: db_path,
        sqlite_auto_migrate: true,
        ..Config::default()
    })
    .await
    .unwrap();
    let store = context.sqlite_store.as_ref().unwrap();
    store
        .upsert_ai_temp_policy(&crate::storage::AiTempPolicyUpsert {
            source_report_id: None,
            policy_key: "policy-effect".to_string(),
            title: "policy effect".to_string(),
            policy_type: "tighten_route_cc".to_string(),
            layer: "l7".to_string(),
            scope_type: "route".to_string(),
            scope_value: "/api/login".to_string(),
            action: "tighten_route_cc".to_string(),
            operator: "exact".to_string(),
            suggested_value: "45".to_string(),
            rationale: "test".to_string(),
            confidence: 90,
            auto_applied: true,
            expires_at: unix_timestamp() + 600,
            effect_stats: Some(crate::storage::AiTempPolicyEffectStats {
                total_hits: 8,
                post_policy_observations: 8,
                outcome_status: Some("effective".to_string()),
                outcome_score: 24,
                ..crate::storage::AiTempPolicyEffectStats::default()
            }),
        })
        .await
        .unwrap();

    let snapshot = context
        .ai_defense_signal_snapshot(unix_timestamp(), Some("test".to_string()))
        .await
        .unwrap();
    let effect = snapshot
        .policy_effects
        .iter()
        .find(|item| item.policy_key == "policy-effect")
        .expect("policy effect should be present");

    assert_eq!(effect.outcome_status, "effective");
    assert_eq!(effect.outcome_score, 24);
    assert_eq!(effect.observations, 8);
}

#[tokio::test]
async fn test_ai_auto_defense_revokes_harmful_temp_policy() {
    let db_path = unique_test_db_path("ai_policy_effect_revoke");
    let context = WafContext::new(Config {
        sqlite_enabled: true,
        sqlite_path: db_path,
        sqlite_auto_migrate: true,
        ..Config::default()
    })
    .await
    .unwrap();
    let store = context.sqlite_store.as_ref().unwrap();
    store
        .upsert_ai_temp_policy(&crate::storage::AiTempPolicyUpsert {
            source_report_id: None,
            policy_key: "harmful-policy".to_string(),
            title: "harmful policy".to_string(),
            policy_type: "tighten_route_cc".to_string(),
            layer: "l7".to_string(),
            scope_type: "route".to_string(),
            scope_value: "/api/login".to_string(),
            action: "tighten_route_cc".to_string(),
            operator: "exact".to_string(),
            suggested_value: "45".to_string(),
            rationale: "test".to_string(),
            confidence: 90,
            auto_applied: true,
            expires_at: unix_timestamp() + 600,
            effect_stats: Some(crate::storage::AiTempPolicyEffectStats {
                post_policy_observations: 6,
                post_policy_upstream_errors: 5,
                suspected_false_positive_events: 3,
                outcome_status: Some("harmful".to_string()),
                outcome_score: -40,
                ..crate::storage::AiTempPolicyEffectStats::default()
            }),
        })
        .await
        .unwrap();

    context
        .run_ai_auto_defense(unix_timestamp(), Some("test".to_string()))
        .await
        .unwrap();

    let active = store
        .list_active_ai_temp_policies(unix_timestamp())
        .await
        .unwrap();
    assert!(active.is_empty());
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
