use super::*;

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

#[tokio::test]
async fn test_ai_temp_policy_local_block_records_outcome_feedback() {
    let db_path = unique_test_db_path("ai_policy_local_block_outcome");
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
            policy_key: "local-block-policy".to_string(),
            title: "local block policy".to_string(),
            policy_type: "add_temp_block".to_string(),
            layer: "l7".to_string(),
            scope_type: "route".to_string(),
            scope_value: "/api/login".to_string(),
            action: "add_temp_block".to_string(),
            operator: "exact".to_string(),
            suggested_value: "block".to_string(),
            rationale: "test".to_string(),
            confidence: 90,
            auto_applied: true,
            expires_at: unix_timestamp() + 600,
            effect_stats: Some(crate::storage::AiTempPolicyEffectStats::default()),
        })
        .await
        .unwrap();
    context.refresh_ai_temp_policies().await.unwrap();

    let mut request = crate::protocol::UnifiedHttpRequest::new(
        crate::protocol::HttpVersion::Http1_1,
        "POST".to_string(),
        "/api/login".to_string(),
    );
    request.set_client_ip("203.0.113.25".to_string());
    request.add_header("Host".to_string(), "example.com".to_string());
    request.add_metadata("gateway.site_id".to_string(), "site-a".to_string());

    let result = context
        .apply_ai_temp_policies_to_request(&mut request)
        .expect("local block policy should match");
    assert!(result.blocked);
    assert_eq!(
        request
            .get_metadata("ai.policy.matched_count")
            .map(String::as_str),
        Some("1")
    );

    context.note_ai_route_result(
        &request,
        AiRouteResultObservation {
            status_code: 499,
            latency_ms: None,
            upstream_error: false,
            local_response: true,
            blocked: true,
        },
    );
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    let active = store
        .list_active_ai_temp_policies(unix_timestamp())
        .await
        .unwrap();
    let effect =
        serde_json::from_str::<crate::storage::AiTempPolicyEffectStats>(&active[0].effect_json)
            .unwrap();
    assert_eq!(effect.total_hits, 1);
    assert_eq!(effect.post_policy_observations, 1);
    assert_eq!(effect.post_policy_status_codes.get("499").copied(), Some(1));
    assert_eq!(effect.outcome_status.as_deref(), Some("warming"));
}
