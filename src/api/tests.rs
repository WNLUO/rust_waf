use super::*;
use crate::config::{Rule, RuleAction, RuleLayer, Severity};
use crate::storage::{LocalCertificateEntry, LocalSiteEntry, SiteSyncLinkEntry, SqliteStore};
use std::time::{SystemTime, UNIX_EPOCH};

fn unique_test_db_path(name: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    std::env::temp_dir()
        .join(format!(
            "{}_api_{}_{}.db",
            env!("CARGO_PKG_NAME"),
            name,
            nanos
        ))
        .display()
        .to_string()
}

#[test]
fn test_build_metrics_response_without_sources() {
    let response = build_metrics_response(
        None,
        0,
        None,
        None,
        None,
        crate::core::RuntimePressureSnapshot {
            level: "normal",
            capacity_class: "standard",
            defense_depth: "balanced",
            storage_queue_usage_percent: 0,
            cpu_usage_percent: 0.0,
            cpu_pressure_score: 0,
            cpu_sample_available: false,
            drop_delay: false,
            trim_event_persistence: false,
            l7_bucket_limit: 32_768,
            l7_page_window_limit: 12_288,
            behavior_bucket_limit: 16_384,
            behavior_sample_stride: 1,
            prefer_drop: false,
        },
        crate::core::ResourceSentinelSnapshot::default(),
        &[],
        crate::config::Config::default()
            .integrations
            .ai_audit
            .max_active_temp_policies,
    );

    assert_eq!(response.total_packets, 0);
    assert_eq!(response.blocked_packets, 0);
    assert_eq!(response.active_rules, 0);
    assert!(!response.sqlite_enabled);
    assert_eq!(response.persisted_security_events, 0);
    assert_eq!(response.persisted_blocked_ips, 0);
    assert_eq!(response.persisted_rules, 0);
    assert!(response.last_persisted_event_at.is_none());
    assert!(response.last_rule_update_at.is_none());
    assert_eq!(response.l4_bucket_count, 0);
    assert_eq!(response.l4_overload_level, "normal");
    assert_eq!(response.runtime_pressure_level, "normal");
    assert_eq!(response.runtime_capacity_class, "standard");
    assert_eq!(response.runtime_defense_depth, "balanced");
    assert!(!response.runtime_pressure_drop_delay);
    assert!(!response.runtime_pressure_trim_event_persistence);
    assert_eq!(response.runtime_pressure_storage_queue_percent, 0);
    assert!(response.storage_degraded_reasons.is_empty());
    assert_eq!(response.storage_attack_insights.active_bucket_count, 0);
    assert_eq!(response.ai_temp_policies.active_count, 0);
    assert_eq!(response.ai_temp_policies.effective_count, 0);
}

#[test]
fn test_build_metrics_response_with_sources() {
    let response = build_metrics_response(
        Some(crate::metrics::MetricsSnapshot {
            total_packets: 12,
            blocked_packets: 3,
            blocked_l4: 1,
            blocked_l7: 2,
            l7_cc_challenges: 5,
            l7_cc_blocks: 2,
            l7_cc_delays: 7,
            l7_cc_unresolved_identity_delays: 3,
            l7_cc_verified_passes: 4,
            total_bytes: 1024,
            proxied_requests: 10,
            proxy_successes: 8,
            proxy_failures: 2,
            proxy_fail_close_rejections: 1,
            l4_bucket_budget_rejections: 4,
            tls_pre_handshake_rejections: 2,
            trusted_proxy_permit_drops: 2,
            trusted_proxy_l4_degrade_actions: 9,
            tls_handshake_timeouts: 3,
            tls_handshake_failures: 1,
            upstream_healthcheck_successes: 5,
            upstream_healthcheck_failures: 1,
            proxy_latency_micros_total: 40_000,
            average_proxy_latency_micros: 5_000,
            document_proxy: crate::metrics::ProxyTrafficMetricsSnapshot::default(),
            api_proxy: crate::metrics::ProxyTrafficMetricsSnapshot::default(),
            static_proxy: crate::metrics::ProxyTrafficMetricsSnapshot::default(),
            other_proxy: crate::metrics::ProxyTrafficMetricsSnapshot::default(),
            top_host_segments: Vec::new(),
            top_route_segments: Vec::new(),
            top_host_route_segments: Vec::new(),
            ..crate::metrics::MetricsSnapshot::default()
        }),
        4,
        Some(crate::storage::StorageMetricsSummary {
            security_events: 7,
            blocked_ips: 2,
            latest_event_at: Some(1234567890),
            rules: 5,
            latest_rule_update_at: Some(1234567899),
            queue_capacity: 1024,
            queue_depth: 6,
            dropped_security_events: 3,
            dropped_blocked_ips: 1,
        }),
        Some(crate::storage::StorageAggregationInsightSummary {
            active_bucket_count: 4,
            active_event_count: 22,
            long_tail_bucket_count: 1,
            long_tail_event_count: 9,
            hotspot_sources: vec![crate::storage::StorageAggregationHotspot {
                source_ip: "203.0.113.8".to_string(),
                action: "alert".to_string(),
                route: Some("/login".to_string()),
                count: 7,
                time_window_start: 120,
                time_window_end: 125,
            }],
        }),
        Some(crate::l4::behavior::L4BehaviorOverview {
            bucket_count: 9,
            fine_grained_buckets: 5,
            coarse_buckets: 3,
            peer_only_buckets: 1,
            direct_idle_no_request_buckets: 2,
            direct_idle_no_request_connections: 4,
            normal_buckets: 4,
            suspicious_buckets: 3,
            high_risk_buckets: 2,
            safeline_feedback_hits: 6,
            l7_feedback_hits: 8,
            dropped_events: 11,
            overload_level: crate::l4::behavior::L4OverloadLevel::High,
            overload_reason: Some("bucket_pressure".to_string()),
        }),
        crate::core::RuntimePressureSnapshot {
            level: "high",
            capacity_class: "small",
            defense_depth: "lean",
            storage_queue_usage_percent: 81,
            cpu_usage_percent: 92.0,
            cpu_pressure_score: 2,
            cpu_sample_available: true,
            drop_delay: true,
            trim_event_persistence: true,
            l7_bucket_limit: 8_192,
            l7_page_window_limit: 2_048,
            behavior_bucket_limit: 4_096,
            behavior_sample_stride: 2,
            prefer_drop: true,
        },
        crate::core::ResourceSentinelSnapshot {
            mode: "under_attack".to_string(),
            attack_score: 88,
            tracked_debt_buckets: 12,
            high_debt_buckets: 3,
            extreme_debt_buckets: 1,
            tracked_attack_clusters: 1,
            active_cooldowns: 1,
            pre_admission_rejections: 7,
            aggregated_events: 9,
            automated_defense_actions: 4,
            automated_defense_extensions: 2,
            automated_defense_relaxations: 1,
            automated_defense_memory_hits: 3,
            automated_audit_events: 1,
            top_attack_clusters: vec![crate::core::ResourceSentinelClusterSnapshot {
                cluster: "203.0.113.0/24".to_string(),
                attack_type: "slow_tls_handshake".to_string(),
                transport: "tls".to_string(),
                reason: "timeout".to_string(),
                sample_ip: "203.0.113.9".to_string(),
                count: 20,
                admitted: 1,
                rejected: 2,
                aggregated: 3,
                score: 200,
                first_seen_ms: 1,
                last_seen_ms: 2,
            }],
            defense_action_effects: vec![crate::core::ResourceSentinelDefenseActionEffect {
                attack_type: "slow_tls_handshake".to_string(),
                preferred_action: "tls_pre_admission_cooldown".to_string(),
                effective_score: 3,
                ineffective_score: 1,
                weak_score: 1,
                harmful_score: 0,
                confidence: 75,
                last_outcome: "effective".to_string(),
                last_rejection_delta: 9,
                last_score_delta: -12,
                last_seen_ms: 3,
            }],
            defense_decision_traces: vec![crate::core::ResourceSentinelDefenseDecisionTrace {
                attack_type: "slow_tls_handshake".to_string(),
                selected_action: "cluster_connection_cooldown".to_string(),
                default_action: "tls_pre_admission_cooldown".to_string(),
                reason: "harmful_memory_switched".to_string(),
                mode: "under_attack".to_string(),
                memory_outcome: "harmful".to_string(),
                confidence: 25,
                effective_score: 1,
                ineffective_score: 3,
                weak_score: 1,
                harmful_score: 2,
                used_memory: true,
                switched_action: true,
                observed_at_ms: 4,
            }],
            ingress_gap_analysis: crate::core::ResourceSentinelIngressGapAnalysis {
                cdn_observed_requests: None,
                rust_observed_intercepts: 16,
                estimated_outer_layer_absorption_ratio: None,
                likely_absorption_layer: "transport_or_cdn_edge".to_string(),
                confidence: "medium".to_string(),
                summary: "Rust 侧观测以传输层/连接型压力为主。".to_string(),
            },
            resource_pressure_feedback: crate::core::ResourceSentinelResourcePressureFeedback {
                pressure_level: "high".to_string(),
                storage_queue_usage_percent: 81,
                fast_path_activations: 0,
                resource_outcome: "resource_under_attack".to_string(),
                scoring_hint: "continue_effect_scoring".to_string(),
                summary: "资源压力 high。".to_string(),
            },
            attack_migrations: vec![crate::core::ResourceSentinelAttackMigration {
                from_cluster: "203.0.114.0/24".to_string(),
                to_cluster: "203.0.113.0/24".to_string(),
                from_attack_type: "idle_no_request".to_string(),
                to_attack_type: "slow_tls_handshake".to_string(),
                detected_at_ms: 5,
                reason: "top_attack_cluster_shift_with_continuous_pressure".to_string(),
                confidence: "medium".to_string(),
            }],
            attack_report_preview: Some(crate::core::ResourceSentinelAttackReport {
                session_id: 42,
                generated_at_ms: 6,
                summary: "攻击会话 #42 当前阶段 started。".to_string(),
                what_worked: vec!["slow_tls_handshake 使用 tls_pre_admission_cooldown".to_string()],
                what_was_weak: vec![],
                what_was_harmful: vec![],
                cdn_rust_gap_analysis: "Rust 侧观测以传输层/连接型压力为主。".to_string(),
                resource_pressure_summary: "资源压力 high。".to_string(),
                recommendations: vec!["继续观察当前自动化策略效果评分。".to_string()],
            }),
            attack_diagnosis: crate::core::ResourceSentinelAttackDiagnosis {
                severity: "high".to_string(),
                primary_pressure: "tls_handshake_resource".to_string(),
                summary: "哨兵级别为 high，主要压力判断为 tls_handshake_resource，自动防御状态为 defense_effective_extending。最热簇为 203.0.113.0/24，类型 slow_tls_handshake，样本 IP 203.0.113.9，累计 20 次、风险分 200。".to_string(),
                active_defense: "defense_effective_extending".to_string(),
                recommended_next_action: "keep_current_automation_and_watch_decay".to_string(),
                evidence: vec![
                    "mode=under_attack attack_score=88".to_string(),
                    "top_cluster=203.0.113.0/24 attack_type=slow_tls_handshake transport=tls reason=timeout count=20 score=200 sample_ip=203.0.113.9".to_string(),
                ],
                top_cluster: None,
            },
            attack_lifecycle: crate::core::ResourceSentinelAttackLifecycle {
                phase: "started".to_string(),
                previous_phase: "normal".to_string(),
                phase_since_ms: 0,
                transitioned: true,
            },
            attack_session: crate::core::ResourceSentinelAttackSession {
                session_id: 42,
                phase: "started".to_string(),
                started_at_ms: 1,
                ended_at_ms: None,
                duration_ms: 1234,
                peak_severity: "high".to_string(),
                peak_attack_score: 88,
                primary_pressure: "tls_handshake_resource".to_string(),
                top_clusters: vec![],
                defense_actions: 4,
                defense_extensions: 2,
                defense_relaxations: 1,
                audit_event_count: 1,
                pre_admission_rejections: 7,
                aggregated_events: 9,
                final_outcome: "active".to_string(),
                summary: "攻击会话 #42 持续 1234ms，峰值等级 high，主压力 tls_handshake_resource。"
                    .to_string(),
            },
        },
        &[
            crate::storage::AiTempPolicyEntry {
                id: 1,
                created_at: 100,
                updated_at: 120,
                expires_at: 900,
                status: "active".to_string(),
                source_report_id: None,
                policy_key: "policy-effective".to_string(),
                title: "effective policy".to_string(),
                policy_type: "tighten_route_cc".to_string(),
                layer: "L7".to_string(),
                scope_type: "route".to_string(),
                scope_value: "/api/login".to_string(),
                action: "tighten_route_cc".to_string(),
                operator: "exact".to_string(),
                suggested_value: "45".to_string(),
                rationale: "test".to_string(),
                confidence: 90,
                auto_applied: true,
                hit_count: 8,
                last_hit_at: Some(130),
                effect_json: serde_json::to_string(&crate::storage::AiTempPolicyEffectStats {
                    total_hits: 8,
                    post_policy_observations: 6,
                    auto_extensions: 1,
                    outcome_status: Some("effective".to_string()),
                    outcome_score: 24,
                    ..crate::storage::AiTempPolicyEffectStats::default()
                })
                .unwrap(),
            },
            crate::storage::AiTempPolicyEntry {
                id: 2,
                created_at: 110,
                updated_at: 140,
                expires_at: 910,
                status: "active".to_string(),
                source_report_id: None,
                policy_key: "policy-harmful".to_string(),
                title: "harmful policy".to_string(),
                policy_type: "increase_challenge".to_string(),
                layer: "L7".to_string(),
                scope_type: "identity".to_string(),
                scope_value: "ipua:203.0.113.1|bot".to_string(),
                action: "increase_challenge".to_string(),
                operator: "exact".to_string(),
                suggested_value: "true".to_string(),
                rationale: "test".to_string(),
                confidence: 85,
                auto_applied: true,
                hit_count: 3,
                last_hit_at: Some(145),
                effect_json: serde_json::to_string(&crate::storage::AiTempPolicyEffectStats {
                    total_hits: 3,
                    post_policy_observations: 5,
                    auto_revoked: true,
                    outcome_status: Some("harmful".to_string()),
                    outcome_score: -30,
                    ..crate::storage::AiTempPolicyEffectStats::default()
                })
                .unwrap(),
            },
        ],
        16,
    );

    assert_eq!(response.total_packets, 12);
    assert_eq!(response.blocked_packets, 3);
    assert_eq!(response.blocked_l4, 1);
    assert_eq!(response.blocked_l7, 2);
    assert_eq!(response.l7_cc_challenges, 5);
    assert_eq!(response.l7_cc_blocks, 2);
    assert_eq!(response.l7_cc_delays, 7);
    assert_eq!(response.l7_cc_unresolved_identity_delays, 3);
    assert_eq!(response.l7_cc_verified_passes, 4);
    assert_eq!(response.total_bytes, 1024);
    assert_eq!(response.proxied_requests, 10);
    assert_eq!(response.proxy_successes, 8);
    assert_eq!(response.proxy_failures, 2);
    assert_eq!(response.proxy_fail_close_rejections, 1);
    assert_eq!(response.l4_bucket_budget_rejections, 4);
    assert_eq!(response.tls_pre_handshake_rejections, 2);
    assert_eq!(response.trusted_proxy_permit_drops, 2);
    assert_eq!(response.trusted_proxy_l4_degrade_actions, 9);
    assert_eq!(response.tls_handshake_timeouts, 3);
    assert_eq!(response.tls_handshake_failures, 1);
    assert_eq!(response.upstream_healthcheck_successes, 5);
    assert_eq!(response.upstream_healthcheck_failures, 1);
    assert_eq!(response.proxy_latency_micros_total, 40_000);
    assert_eq!(response.average_proxy_latency_micros, 5_000);
    assert_eq!(response.active_rules, 4);
    assert!(response.sqlite_enabled);
    assert_eq!(response.persisted_security_events, 7);
    assert_eq!(response.persisted_blocked_ips, 2);
    assert_eq!(response.persisted_rules, 5);
    assert_eq!(response.sqlite_queue_capacity, 1024);
    assert_eq!(response.sqlite_queue_depth, 6);
    assert_eq!(response.sqlite_dropped_security_events, 3);
    assert_eq!(response.sqlite_dropped_blocked_ips, 1);
    assert_eq!(response.last_persisted_event_at, Some(1234567890));
    assert_eq!(response.last_rule_update_at, Some(1234567899));
    assert_eq!(response.l4_bucket_count, 9);
    assert_eq!(response.l4_fine_grained_buckets, 5);
    assert_eq!(response.l4_coarse_buckets, 3);
    assert_eq!(response.l4_peer_only_buckets, 1);
    assert_eq!(response.l4_high_risk_buckets, 2);
    assert_eq!(response.l4_behavior_dropped_events, 11);
    assert_eq!(response.l4_overload_level, "high");
    assert_eq!(response.runtime_pressure_level, "high");
    assert_eq!(response.runtime_capacity_class, "small");
    assert_eq!(response.runtime_defense_depth, "lean");
    assert!(response.runtime_pressure_drop_delay);
    assert!(response.runtime_pressure_trim_event_persistence);
    assert_eq!(response.runtime_pressure_storage_queue_percent, 81);
    assert_eq!(response.resource_sentinel_mode, "under_attack");
    assert_eq!(response.resource_sentinel_attack_score, 88);
    assert_eq!(response.resource_sentinel_pre_admission_rejections, 7);
    assert_eq!(response.resource_sentinel_automated_defense_actions, 4);
    assert_eq!(response.resource_sentinel_automated_defense_extensions, 2);
    assert_eq!(response.resource_sentinel_automated_defense_relaxations, 1);
    assert_eq!(response.resource_sentinel_automated_defense_memory_hits, 3);
    assert_eq!(response.resource_sentinel_automated_audit_events, 1);
    assert_eq!(
        response.resource_sentinel_attack_diagnosis.primary_pressure,
        "tls_handshake_resource"
    );
    assert_eq!(
        response
            .resource_sentinel_attack_diagnosis
            .recommended_next_action,
        "keep_current_automation_and_watch_decay"
    );
    assert_eq!(response.resource_sentinel_attack_lifecycle.phase, "started");
    assert_eq!(response.resource_sentinel_attack_session.session_id, 42);
    assert_eq!(
        response.resource_sentinel_attack_session.primary_pressure,
        "tls_handshake_resource"
    );
    assert_eq!(response.resource_sentinel_tracked_attack_clusters, 1);
    assert_eq!(response.resource_sentinel_active_cooldowns, 1);
    assert_eq!(
        response.resource_sentinel_top_attack_clusters[0].attack_type,
        "slow_tls_handshake"
    );
    assert_eq!(
        response.resource_sentinel_top_attack_clusters[0].rejected,
        2
    );
    assert_eq!(
        response.resource_sentinel_defense_action_effects[0].preferred_action,
        "tls_pre_admission_cooldown"
    );
    assert_eq!(
        response.resource_sentinel_defense_action_effects[0].confidence,
        75
    );
    assert_eq!(
        response.resource_sentinel_defense_decision_traces[0].reason,
        "harmful_memory_switched"
    );
    assert!(response.resource_sentinel_defense_decision_traces[0].switched_action);
    assert_eq!(
        response
            .resource_sentinel_ingress_gap_analysis
            .likely_absorption_layer,
        "transport_or_cdn_edge"
    );
    assert_eq!(
        response
            .resource_sentinel_resource_pressure_feedback
            .storage_queue_usage_percent,
        81
    );
    assert_eq!(
        response.resource_sentinel_attack_migrations[0].to_cluster,
        "203.0.113.0/24"
    );
    assert_eq!(
        response
            .resource_sentinel_attack_report_preview
            .as_ref()
            .expect("report preview")
            .session_id,
        42
    );
    assert!(response
        .storage_degraded_reasons
        .contains(&"storage_low_value_event_persistence_trimmed".to_string()));
    assert!(response
        .storage_degraded_reasons
        .contains(&"storage_security_events_dropped_under_pressure".to_string()));
    assert!(response
        .storage_degraded_reasons
        .contains(&"storage_long_tail_sources_merged".to_string()));
    assert_eq!(response.storage_attack_insights.active_bucket_count, 4);
    assert_eq!(response.storage_attack_insights.long_tail_event_count, 9);
    assert_eq!(response.storage_attack_insights.hotspot_sources.len(), 1);
    assert_eq!(
        response.storage_attack_insights.hotspot_sources[0].source_ip,
        "203.0.113.8"
    );
    assert_eq!(response.ai_temp_policies.active_count, 2);
    assert_eq!(response.ai_temp_policies.max_active_count, 16);
    assert_eq!(response.ai_temp_policies.auto_applied_count, 2);
    assert_eq!(response.ai_temp_policies.effective_count, 1);
    assert_eq!(response.ai_temp_policies.harmful_count, 1);
    assert_eq!(response.ai_temp_policies.total_hits, 11);
    assert_eq!(response.ai_temp_policies.total_observations, 11);
    assert_eq!(response.ai_temp_policies.auto_extensions, 1);
    assert_eq!(response.ai_temp_policies.auto_revoked_count, 1);
}

#[test]
fn test_rule_response_from_rule() {
    let response = RuleResponse::from(Rule {
        id: "rule-2".to_string(),
        name: "Alert Probe".to_string(),
        enabled: false,
        layer: RuleLayer::L4,
        pattern: "probe".to_string(),
        action: RuleAction::Alert,
        severity: Severity::Medium,
        plugin_template_id: None,
        response_template: None,
    });

    assert_eq!(response.id, "rule-2");
    assert_eq!(response.layer, "l4");
    assert_eq!(response.action, "alert");
    assert_eq!(response.severity, "medium");
}

#[test]
fn test_events_query_params_into_query() {
    let query = EventsQueryParams {
        limit: Some(25),
        offset: Some(10),
        layer: Some("L7".to_string()),
        provider: Some("safeline".to_string()),
        provider_site_id: Some("site-1".to_string()),
        source_ip: Some("10.0.0.1".to_string()),
        action: Some("block".to_string()),
        identity_state: Some("trusted_cdn_forwarded".to_string()),
        primary_signal: Some("l7_behavior:delay:250ms".to_string()),
        labels: Some("identity:trusted_cdn_forwarded, l7_rules:lightweight".to_string()),
        blocked_only: Some(true),
        handled_only: Some(true),
        created_from: Some(100),
        created_to: Some(200),
        sort_by: Some("source_ip".to_string()),
        sort_direction: Some("asc".to_string()),
    }
    .into_query();

    let query = query.unwrap();
    assert_eq!(query.limit, 25);
    assert_eq!(query.offset, 10);
    assert_eq!(query.layer.as_deref(), Some("L7"));
    assert_eq!(query.provider.as_deref(), Some("safeline"));
    assert_eq!(query.provider_site_id.as_deref(), Some("site-1"));
    assert_eq!(query.source_ip.as_deref(), Some("10.0.0.1"));
    assert_eq!(query.action.as_deref(), Some("block"));
    assert_eq!(
        query.identity_state.as_deref(),
        Some("trusted_cdn_forwarded")
    );
    assert_eq!(
        query.primary_signal.as_deref(),
        Some("l7_behavior:delay:250ms")
    );
    assert_eq!(
        query.labels,
        vec![
            "identity:trusted_cdn_forwarded".to_string(),
            "l7_rules:lightweight".to_string()
        ]
    );
    assert!(query.blocked_only);
    assert_eq!(query.created_from, Some(100));
    assert_eq!(query.created_to, Some(200));
    assert!(matches!(
        query.sort_by,
        crate::storage::EventSortField::SourceIp
    ));
    assert!(matches!(
        query.sort_direction,
        crate::storage::SortDirection::Asc
    ));
}

#[test]
fn test_blocked_ips_query_params_into_query() {
    let query = BlockedIpsQueryParams {
        limit: Some(5),
        offset: Some(2),
        source_scope: Some("local".to_string()),
        provider: Some("safeline".to_string()),
        ip: Some("10.0.0.2".to_string()),
        keyword: Some(" rate ".to_string()),
        active_only: Some(true),
        blocked_from: Some(300),
        blocked_to: Some(400),
        sort_by: Some("ip".to_string()),
        sort_direction: Some("asc".to_string()),
    }
    .into_query();

    let query = query.unwrap();
    assert_eq!(query.limit, 5);
    assert_eq!(query.offset, 2);
    assert!(matches!(
        query.source_scope,
        crate::storage::BlockedIpSourceScope::Local
    ));
    assert_eq!(query.provider.as_deref(), Some("safeline"));
    assert_eq!(query.ip.as_deref(), Some("10.0.0.2"));
    assert_eq!(query.keyword.as_deref(), Some("rate"));
    assert!(query.active_only);
    assert_eq!(query.blocked_from, Some(300));
    assert_eq!(query.blocked_to, Some(400));
    assert!(matches!(
        query.sort_by,
        crate::storage::BlockedIpSortField::Ip
    ));
}

#[test]
fn test_blocked_ips_query_keyword_empty_becomes_none() {
    let query = BlockedIpsQueryParams {
        keyword: Some("   ".to_string()),
        ..BlockedIpsQueryParams::default()
    }
    .into_query()
    .unwrap();

    assert_eq!(query.keyword, None);
}

#[test]
fn test_invalid_sort_params_fail_validation() {
    let invalid_events = EventsQueryParams {
        sort_by: Some("unknown".to_string()),
        ..EventsQueryParams::default()
    }
    .into_query();
    assert!(invalid_events.is_err());

    let invalid_blocked = BlockedIpsQueryParams {
        source_scope: Some("sideways".to_string()),
        ..BlockedIpsQueryParams::default()
    }
    .into_query();
    assert!(invalid_blocked.is_err());

    let invalid_blocked_sort = BlockedIpsQueryParams {
        sort_direction: Some("sideways".to_string()),
        ..BlockedIpsQueryParams::default()
    }
    .into_query();
    assert!(invalid_blocked_sort.is_err());
}

#[test]
fn test_safeline_mapping_update_rejects_duplicate_site_ids() {
    let payload = SafeLineMappingsUpdateRequest {
        mappings: vec![
            SafeLineMappingUpsertRequest {
                safeline_site_id: "site-1".to_string(),
                safeline_site_name: "portal".to_string(),
                safeline_site_domain: "portal.example.com".to_string(),
                local_alias: "门户".to_string(),
                enabled: true,
                is_primary: false,
                notes: "".to_string(),
            },
            SafeLineMappingUpsertRequest {
                safeline_site_id: "site-1".to_string(),
                safeline_site_name: "portal-dup".to_string(),
                safeline_site_domain: "portal-dup.example.com".to_string(),
                local_alias: "门户副本".to_string(),
                enabled: true,
                is_primary: false,
                notes: "".to_string(),
            },
        ],
        allow_empty_replace: None,
    };

    let error = payload.into_storage_mappings().unwrap_err();
    assert!(error.contains("重复映射"));
}

#[test]
fn test_safeline_mapping_update_rejects_disabled_primary() {
    let payload = SafeLineMappingsUpdateRequest {
        mappings: vec![SafeLineMappingUpsertRequest {
            safeline_site_id: "site-1".to_string(),
            safeline_site_name: "portal".to_string(),
            safeline_site_domain: "portal.example.com".to_string(),
            local_alias: "门户".to_string(),
            enabled: false,
            is_primary: true,
            notes: "".to_string(),
        }],
        allow_empty_replace: None,
    };

    let error = payload.into_storage_mappings().unwrap_err();
    assert!(error.contains("必须保持启用状态"));
}

#[tokio::test]
async fn test_local_site_request_normalizes_primary_hostname() {
    let path = unique_test_db_path("local_site_request");
    let store = SqliteStore::new(path, true).await.unwrap();

    let site = LocalSiteUpsertRequest {
        name: " Portal ".to_string(),
        primary_hostname: " portal.example.com ".to_string(),
        hostnames: vec!["www.portal.example.com".to_string()],
        listen_ports: vec![" 443 ".to_string(), "443".to_string()],
        upstreams: vec![
            " http://127.0.0.1:8080 ".to_string(),
            "http://127.0.0.1:8080".to_string(),
        ],
        safeline_intercept: None,
        enabled: true,
        tls_enabled: true,
        local_certificate_id: None,
        source: " ".to_string(),
        sync_mode: " ".to_string(),
        notes: " prod ".to_string(),
        last_synced_at: Some(123),
        expected_updated_at: None,
    }
    .into_storage_site(&store)
    .await
    .unwrap();

    assert_eq!(site.name, "Portal");
    assert_eq!(site.primary_hostname, "portal.example.com");
    assert_eq!(
        site.hostnames,
        vec![
            "portal.example.com".to_string(),
            "www.portal.example.com".to_string()
        ]
    );
    assert!(site.listen_ports.is_empty());
    assert_eq!(site.upstreams, vec!["http://127.0.0.1:8080".to_string()]);
    assert_eq!(site.source, "manual");
    assert_eq!(site.sync_mode, "manual");
    assert_eq!(site.notes, "prod");
}

#[tokio::test]
async fn test_local_site_request_rejects_missing_certificate_reference() {
    let path = unique_test_db_path("local_site_missing_cert");
    let store = SqliteStore::new(path, true).await.unwrap();

    let error = LocalSiteUpsertRequest {
        name: "Portal".to_string(),
        primary_hostname: "portal.example.com".to_string(),
        hostnames: Vec::new(),
        listen_ports: Vec::new(),
        upstreams: Vec::new(),
        safeline_intercept: None,
        enabled: true,
        tls_enabled: true,
        local_certificate_id: Some(999),
        source: "manual".to_string(),
        sync_mode: "manual".to_string(),
        notes: String::new(),
        last_synced_at: None,
        expected_updated_at: None,
    }
    .into_storage_site(&store)
    .await
    .unwrap_err();

    assert!(error.contains("本地证书"));
}

#[test]
fn test_local_certificate_request_validates_time_range() {
    let error = LocalCertificateUpsertRequest {
        name: "portal cert".to_string(),
        domains: vec!["portal.example.com".to_string()],
        issuer: "Acme".to_string(),
        valid_from: Some(200),
        valid_to: Some(100),
        source_type: "manual".to_string(),
        provider_remote_id: Some("31".to_string()),
        provider_remote_domains: vec!["portal.example.com".to_string()],
        last_remote_fingerprint: Some("fp31".to_string()),
        sync_status: "synced".to_string(),
        sync_message: String::new(),
        auto_sync_enabled: false,
        trusted: true,
        expired: false,
        notes: String::new(),
        last_synced_at: None,
        certificate_pem: None,
        private_key_pem: None,
        clear_secret: None,
        expected_updated_at: None,
    }
    .into_storage_certificate()
    .unwrap_err();

    assert!(error.contains("有效期结束时间"));
}

#[tokio::test]
async fn test_site_sync_link_request_requires_existing_local_site() {
    let path = unique_test_db_path("site_link_missing_site");
    let store = SqliteStore::new(path, true).await.unwrap();

    let error = SiteSyncLinkUpsertRequest {
        local_site_id: 404,
        provider: "safeline".to_string(),
        remote_site_id: "site-1".to_string(),
        remote_site_name: String::new(),
        remote_cert_id: None,
        sync_mode: String::new(),
        last_local_hash: None,
        last_remote_hash: None,
        last_error: None,
        last_synced_at: None,
    }
    .into_storage_link(&store)
    .await
    .unwrap_err();

    assert!(error.contains("本地站点"));
}

#[test]
fn test_local_site_response_parses_json_fields() {
    let response = LocalSiteResponse::try_from(LocalSiteEntry {
        id: 1,
        name: "Portal".to_string(),
        primary_hostname: "portal.example.com".to_string(),
        hostnames_json: r#"["portal.example.com","www.portal.example.com"]"#.to_string(),
        listen_ports_json: r#"["80","443"]"#.to_string(),
        upstreams_json: r#"["http://127.0.0.1:8080"]"#.to_string(),
        safeline_intercept_json: None,
        enabled: true,
        tls_enabled: true,
        local_certificate_id: Some(3),
        source: "manual".to_string(),
        sync_mode: "manual".to_string(),
        notes: String::new(),
        last_synced_at: Some(123),
        created_at: 100,
        updated_at: 200,
    })
    .unwrap();

    assert_eq!(response.hostnames.len(), 2);
    assert_eq!(response.listen_ports, vec!["80", "443"]);
    assert_eq!(response.upstreams, vec!["http://127.0.0.1:8080"]);
}

#[test]
fn test_local_certificate_response_parses_json_fields() {
    let response = LocalCertificateResponse::try_from(LocalCertificateEntry {
        id: 1,
        name: "Portal".to_string(),
        domains_json: r#"["portal.example.com","api.example.com"]"#.to_string(),
        issuer: "Acme".to_string(),
        valid_from: Some(100),
        valid_to: Some(200),
        source_type: "manual".to_string(),
        provider_remote_id: Some("31".to_string()),
        provider_remote_domains_json: r#"["portal.example.com","api.example.com"]"#.to_string(),
        last_remote_fingerprint: Some("fp31".to_string()),
        sync_status: "synced".to_string(),
        sync_message: "ok".to_string(),
        auto_sync_enabled: true,
        trusted: true,
        expired: false,
        notes: String::new(),
        last_synced_at: Some(123),
        created_at: 100,
        updated_at: 200,
    })
    .unwrap();

    assert_eq!(
        response.domains,
        vec!["portal.example.com", "api.example.com"]
    );
    assert_eq!(response.provider_remote_id.as_deref(), Some("31"));
}

#[test]
fn test_site_sync_link_response_from_storage() {
    let response = SiteSyncLinkResponse::from(SiteSyncLinkEntry {
        id: 1,
        local_site_id: 2,
        provider: "safeline".to_string(),
        remote_site_id: "site-1".to_string(),
        remote_site_name: "portal.example.com".to_string(),
        remote_cert_id: Some("31".to_string()),
        sync_mode: "bidirectional".to_string(),
        last_local_hash: Some("local".to_string()),
        last_remote_hash: Some("remote".to_string()),
        last_error: None,
        last_synced_at: Some(123),
        created_at: 100,
        updated_at: 200,
    });

    assert_eq!(response.provider, "safeline");
    assert_eq!(response.remote_site_id, "site-1");
    assert_eq!(response.remote_cert_id.as_deref(), Some("31"));
}
