use super::*;

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
