use super::*;

#[test]
fn ai_defense_rejects_broad_or_static_routes() {
    assert!(!ai_defense_route_allowed("/"));
    assert!(!ai_defense_route_allowed("/static/app.js"));
    assert!(!ai_defense_route_allowed("/assets/app.css"));
    assert!(!ai_defense_route_allowed("/../admin"));
    assert!(ai_defense_route_allowed("/api/login"));
}

#[test]
fn ai_defense_decision_respects_confidence_guardrail() {
    let mut decision = AiDefenseDecision {
        key: "test".to_string(),
        title: "test".to_string(),
        layer: "l7".to_string(),
        scope_type: "route".to_string(),
        scope_value: "/api/login".to_string(),
        action: "tighten_route_cc".to_string(),
        operator: "exact".to_string(),
        suggested_value: "45".to_string(),
        ttl_secs: 900,
        confidence: 81,
        auto_apply: true,
        rationale: "test".to_string(),
    };

    assert!(!ai_defense_decision_allowed(&decision, 82));
    decision.confidence = 82;
    assert!(ai_defense_decision_allowed(&decision, 82));
    decision.action = "add_temp_block".to_string();
    assert!(!ai_defense_decision_allowed(&decision, 82));
}

#[tokio::test]
async fn ai_defense_snapshot_includes_operational_context() {
    let config = crate::config::Config {
        sqlite_enabled: false,
        ..crate::config::Config::default()
    };
    let context = WafContext::new(config).await.unwrap();
    context.set_upstream_health(false, Some("timeout".to_string()));

    let snapshot = context
        .ai_defense_signal_snapshot(123, Some("test_trigger".to_string()))
        .await
        .unwrap();

    assert_eq!(snapshot.generated_at, 123);
    assert_eq!(snapshot.trigger_reason.as_deref(), Some("test_trigger"));
    assert_eq!(snapshot.runtime_pressure.level, "normal");
    assert!(!snapshot.upstream_health.healthy);
    assert_eq!(
        snapshot.upstream_health.last_error.as_deref(),
        Some("timeout")
    );
    assert!(snapshot.active_policy_summaries.is_empty());
}

#[tokio::test]
async fn ai_defense_snapshot_includes_identity_profile() {
    let config = crate::config::Config {
        sqlite_enabled: false,
        ..crate::config::Config::default()
    };
    let context = WafContext::new(config).await.unwrap();
    let result =
        crate::core::InspectionResult::drop(crate::core::InspectionLayer::L7, "route pressure");

    for idx in 0..3 {
        let mut request = UnifiedHttpRequest::new(
            crate::protocol::HttpVersion::Http1_1,
            "POST".to_string(),
            "/api/login".to_string(),
        );
        request.set_client_ip(format!("203.0.113.{}", idx + 10));
        request.add_header("User-Agent".to_string(), "UnitTest/1.0".to_string());
        request.add_metadata("gateway.site_id".to_string(), "site-a".to_string());
        if idx == 0 {
            request.add_metadata(
                "network.identity_state".to_string(),
                "spoofed_forward_header".to_string(),
            );
        }
        context.note_site_defense_signal(&request, &result);
    }

    let snapshot = context
        .ai_defense_signal_snapshot(unix_timestamp(), Some("test".to_string()))
        .await
        .unwrap();
    let identity = snapshot
        .identity_summaries
        .iter()
        .find(|item| item.site_id == "site-a" && item.route == "/api/login")
        .expect("identity profile should be present");

    assert_eq!(identity.total_events, 3);
    assert_eq!(identity.distinct_client_count, 3);
    assert_eq!(identity.spoofed_forward_header_events, 1);
    assert_eq!(identity.top_user_agents[0].value, "UnitTest/1.0");
    assert_eq!(identity.top_user_agents[0].count, 3);
}
