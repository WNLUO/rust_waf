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
