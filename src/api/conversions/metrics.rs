use super::super::types::{
    AutoTuningEffectEvaluationResponse, AutoTuningEffectSegmentEvaluationResponse,
    AutoTuningRecommendationResponse, AutoTuningRuntimeResponse, L4StatsResponse, L7StatsResponse,
};
use crate::core::WafContext;

impl L4StatsResponse {
    pub(crate) fn disabled() -> Self {
        Self {
            enabled: false,
            behavior: crate::l4::behavior::L4BehaviorSnapshot {
                overview: crate::l4::behavior::L4BehaviorOverview {
                    bucket_count: 0,
                    fine_grained_buckets: 0,
                    coarse_buckets: 0,
                    peer_only_buckets: 0,
                    direct_idle_no_request_buckets: 0,
                    direct_idle_no_request_connections: 0,
                    normal_buckets: 0,
                    suspicious_buckets: 0,
                    high_risk_buckets: 0,
                    safeline_feedback_hits: 0,
                    l7_feedback_hits: 0,
                    dropped_events: 0,
                    overload_level: crate::l4::behavior::L4OverloadLevel::Normal,
                    overload_reason: None,
                },
                top_buckets: Vec::new(),
            },
            connections: crate::l4::connection::ConnectionStats {
                total_connections: 0,
                active_connections: 0,
                blocked_connections: 0,
                rate_limit_hits: 0,
            },
            ddos_events: 0,
            protocol_anomalies: 0,
            traffic: 0,
            defense_actions: 0,
            bloom_stats: None,
            false_positive_stats: None,
            per_port_stats: Vec::new(),
        }
    }

    pub(crate) fn from_stats(stats: crate::l4::inspector::L4Statistics) -> Self {
        let mut per_port_stats = stats.per_port_stats.into_values().collect::<Vec<_>>();
        per_port_stats.sort_by(|left, right| {
            right
                .blocks
                .cmp(&left.blocks)
                .then(right.ddos_events.cmp(&left.ddos_events))
                .then(right.connections.cmp(&left.connections))
                .then(left.port.cmp(&right.port))
        });

        Self {
            enabled: true,
            behavior: stats.behavior,
            connections: stats.connections,
            ddos_events: stats.ddos_events,
            protocol_anomalies: stats.protocol_anomalies,
            traffic: stats.traffic,
            defense_actions: stats.defense_actions,
            bloom_stats: stats.bloom_stats,
            false_positive_stats: stats.false_positive_stats,
            per_port_stats,
        }
    }
}

impl L7StatsResponse {
    pub(crate) fn from_context(context: &WafContext) -> Self {
        let metrics = context.metrics_snapshot();
        let upstream = context.upstream_health_snapshot();
        let http3 = context.http3_runtime_snapshot();
        let auto = context.auto_tuning_snapshot();

        Self {
            enabled: true,
            blocked_requests: metrics.as_ref().map(|value| value.blocked_l7).unwrap_or(0),
            cc_challenge_requests: metrics
                .as_ref()
                .map(|value| value.l7_cc_challenges)
                .unwrap_or(0),
            cc_block_requests: metrics
                .as_ref()
                .map(|value| value.l7_cc_blocks)
                .unwrap_or(0),
            cc_delayed_requests: metrics
                .as_ref()
                .map(|value| value.l7_cc_delays)
                .unwrap_or(0),
            cc_unresolved_identity_delayed_requests: metrics
                .as_ref()
                .map(|value| value.l7_cc_unresolved_identity_delays)
                .unwrap_or(0),
            cc_verified_pass_requests: metrics
                .as_ref()
                .map(|value| value.l7_cc_verified_passes)
                .unwrap_or(0),
            behavior_challenge_requests: metrics
                .as_ref()
                .map(|value| value.l7_behavior_challenges)
                .unwrap_or(0),
            behavior_block_requests: metrics
                .as_ref()
                .map(|value| value.l7_behavior_blocks)
                .unwrap_or(0),
            behavior_delayed_requests: metrics
                .as_ref()
                .map(|value| value.l7_behavior_delays)
                .unwrap_or(0),
            ip_access_allow_requests: metrics
                .as_ref()
                .map(|value| value.l7_ip_access_allows)
                .unwrap_or(0),
            ip_access_alert_requests: metrics
                .as_ref()
                .map(|value| value.l7_ip_access_alerts)
                .unwrap_or(0),
            ip_access_challenge_requests: metrics
                .as_ref()
                .map(|value| value.l7_ip_access_challenges)
                .unwrap_or(0),
            ip_access_block_requests: metrics
                .as_ref()
                .map(|value| value.l7_ip_access_blocks)
                .unwrap_or(0),
            ip_access_verified_pass_requests: metrics
                .as_ref()
                .map(|value| value.l7_ip_access_verified_passes)
                .unwrap_or(0),
            proxied_requests: metrics
                .as_ref()
                .map(|value| value.proxied_requests)
                .unwrap_or(0),
            proxy_successes: metrics
                .as_ref()
                .map(|value| value.proxy_successes)
                .unwrap_or(0),
            proxy_failures: metrics
                .as_ref()
                .map(|value| value.proxy_failures)
                .unwrap_or(0),
            proxy_fail_close_rejections: metrics
                .as_ref()
                .map(|value| value.proxy_fail_close_rejections)
                .unwrap_or(0),
            l4_bucket_budget_rejections: metrics
                .as_ref()
                .map(|value| value.l4_bucket_budget_rejections)
                .unwrap_or(0),
            tls_pre_handshake_rejections: metrics
                .as_ref()
                .map(|value| value.tls_pre_handshake_rejections)
                .unwrap_or(0),
            trusted_proxy_permit_drops: metrics
                .as_ref()
                .map(|value| value.trusted_proxy_permit_drops)
                .unwrap_or(0),
            trusted_proxy_l4_degrade_actions: metrics
                .as_ref()
                .map(|value| value.trusted_proxy_l4_degrade_actions)
                .unwrap_or(0),
            tls_handshake_timeouts: metrics
                .as_ref()
                .map(|value| value.tls_handshake_timeouts)
                .unwrap_or(0),
            tls_handshake_failures: metrics
                .as_ref()
                .map(|value| value.tls_handshake_failures)
                .unwrap_or(0),
            slow_attack_idle_timeouts: metrics
                .as_ref()
                .map(|value| value.slow_attack_idle_timeouts)
                .unwrap_or(0),
            slow_attack_header_timeouts: metrics
                .as_ref()
                .map(|value| value.slow_attack_header_timeouts)
                .unwrap_or(0),
            slow_attack_body_timeouts: metrics
                .as_ref()
                .map(|value| value.slow_attack_body_timeouts)
                .unwrap_or(0),
            slow_attack_tls_handshake_hits: metrics
                .as_ref()
                .map(|value| value.slow_attack_tls_handshake_hits)
                .unwrap_or(0),
            slow_attack_blocks: metrics
                .as_ref()
                .map(|value| value.slow_attack_blocks)
                .unwrap_or(0),
            average_proxy_latency_micros: metrics
                .as_ref()
                .map(|value| value.average_proxy_latency_micros)
                .unwrap_or(0),
            upstream_healthy: upstream.healthy,
            upstream_last_check_at: upstream.last_check_at,
            upstream_last_error: upstream.last_error,
            http3_feature_available: http3.feature_available,
            http3_configured_enabled: http3.configured_enabled,
            http3_tls13_enabled: http3.tls13_enabled,
            http3_certificate_configured: http3.certificate_configured,
            http3_private_key_configured: http3.private_key_configured,
            http3_listener_started: http3.listener_started,
            http3_listener_addr: http3.listener_addr,
            http3_status: http3.status,
            http3_last_error: http3.last_error,
            auto_tuning: AutoTuningRuntimeResponse {
                mode: match auto.mode {
                    crate::config::AutoTuningMode::Off => "off".to_string(),
                    crate::config::AutoTuningMode::Observe => "observe".to_string(),
                    crate::config::AutoTuningMode::Active => "active".to_string(),
                },
                intent: match auto.intent {
                    crate::config::AutoTuningIntent::Conservative => "conservative".to_string(),
                    crate::config::AutoTuningIntent::Balanced => "balanced".to_string(),
                    crate::config::AutoTuningIntent::Aggressive => "aggressive".to_string(),
                },
                controller_state: auto.controller_state,
                detected_cpu_cores: auto.detected_cpu_cores,
                detected_memory_limit_mb: auto.detected_memory_limit_mb,
                last_adjust_at: auto.last_adjust_at,
                last_adjust_reason: auto.last_adjust_reason,
                last_adjust_diff: auto.last_adjust_diff,
                rollback_count_24h: auto.rollback_count_24h,
                cooldown_until: auto.cooldown_until,
                last_effect_evaluation: auto.last_effect_evaluation.map(|value| {
                    AutoTuningEffectEvaluationResponse {
                        status: value.status,
                        observed_at: value.observed_at,
                        sample_requests: value.sample_requests,
                        handshake_timeout_rate_delta_percent: value
                            .handshake_timeout_rate_delta_percent,
                        bucket_reject_rate_delta_percent: value.bucket_reject_rate_delta_percent,
                        avg_proxy_latency_delta_ms: value.avg_proxy_latency_delta_ms,
                        segments: value
                            .segments
                            .into_iter()
                            .map(|segment| AutoTuningEffectSegmentEvaluationResponse {
                                scope_type: segment.scope_type,
                                scope_key: segment.scope_key,
                                host: segment.host,
                                route: segment.route,
                                request_kind: segment.request_kind,
                                sample_requests: segment.sample_requests,
                                avg_proxy_latency_delta_ms: segment.avg_proxy_latency_delta_ms,
                                failure_rate_delta_percent: segment.failure_rate_delta_percent,
                                status: segment.status,
                            })
                            .collect(),
                        summary: value.summary,
                    }
                }),
                last_observed_tls_handshake_timeout_rate_percent: auto
                    .last_observed_tls_handshake_timeout_rate_percent,
                last_observed_bucket_reject_rate_percent: auto
                    .last_observed_bucket_reject_rate_percent,
                last_observed_avg_proxy_latency_ms: auto.last_observed_avg_proxy_latency_ms,
                last_observed_identity_resolution_pressure_percent: auto
                    .last_observed_identity_resolution_pressure_percent,
                last_observed_l7_friction_pressure_percent: auto
                    .last_observed_l7_friction_pressure_percent,
                last_observed_slow_attack_pressure_percent: auto
                    .last_observed_slow_attack_pressure_percent,
                recommendation: AutoTuningRecommendationResponse {
                    l4_normal_connection_budget_per_minute: auto
                        .recommendation
                        .l4_normal_connection_budget_per_minute,
                    l4_suspicious_connection_budget_per_minute: auto
                        .recommendation
                        .l4_suspicious_connection_budget_per_minute,
                    l4_high_risk_connection_budget_per_minute: auto
                        .recommendation
                        .l4_high_risk_connection_budget_per_minute,
                    l4_reject_threshold_percent: auto.recommendation.l4_reject_threshold_percent,
                    l4_critical_reject_threshold_percent: auto
                        .recommendation
                        .l4_critical_reject_threshold_percent,
                    tls_handshake_timeout_ms: auto.recommendation.tls_handshake_timeout_ms,
                },
            },
        }
    }
}
