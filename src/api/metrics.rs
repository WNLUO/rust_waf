use super::types::{
    MetricsResponse, StorageAttackHotspotResponse, StorageAttackInsightsResponse,
};
use crate::core::RuntimePressureSnapshot;

pub(super) fn build_metrics_response(
    metrics: Option<crate::metrics::MetricsSnapshot>,
    active_rules: u64,
    storage_summary: Option<crate::storage::StorageMetricsSummary>,
    aggregation_insights: Option<crate::storage::StorageAggregationInsightSummary>,
    l4_behavior: Option<crate::l4::behavior::L4BehaviorOverview>,
    runtime_pressure: RuntimePressureSnapshot,
) -> MetricsResponse {
    let snapshot = metrics.unwrap_or_default();
    let sqlite_enabled = storage_summary.is_some();
    let storage_summary = storage_summary.unwrap_or_default();
    let aggregation_insights = aggregation_insights.unwrap_or_default();
    let l4_behavior = l4_behavior.unwrap_or(crate::l4::behavior::L4BehaviorOverview {
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
    });
    let storage_degraded_reasons = build_storage_degraded_reasons(
        &storage_summary,
        &aggregation_insights,
        &runtime_pressure,
    );

    MetricsResponse {
        total_packets: snapshot.total_packets,
        blocked_packets: snapshot.blocked_packets,
        blocked_l4: snapshot.blocked_l4,
        blocked_l7: snapshot.blocked_l7,
        l7_cc_challenges: snapshot.l7_cc_challenges,
        l7_cc_blocks: snapshot.l7_cc_blocks,
        l7_cc_delays: snapshot.l7_cc_delays,
        l7_cc_unresolved_identity_delays: snapshot.l7_cc_unresolved_identity_delays,
        l7_cc_verified_passes: snapshot.l7_cc_verified_passes,
        l7_behavior_challenges: snapshot.l7_behavior_challenges,
        l7_behavior_blocks: snapshot.l7_behavior_blocks,
        l7_behavior_delays: snapshot.l7_behavior_delays,
        total_bytes: snapshot.total_bytes,
        proxied_requests: snapshot.proxied_requests,
        proxy_successes: snapshot.proxy_successes,
        proxy_failures: snapshot.proxy_failures,
        proxy_fail_close_rejections: snapshot.proxy_fail_close_rejections,
        l4_bucket_budget_rejections: snapshot.l4_bucket_budget_rejections,
        tls_pre_handshake_rejections: snapshot.tls_pre_handshake_rejections,
        trusted_proxy_permit_drops: snapshot.trusted_proxy_permit_drops,
        trusted_proxy_l4_degrade_actions: snapshot.trusted_proxy_l4_degrade_actions,
        tls_handshake_timeouts: snapshot.tls_handshake_timeouts,
        tls_handshake_failures: snapshot.tls_handshake_failures,
        slow_attack_idle_timeouts: snapshot.slow_attack_idle_timeouts,
        slow_attack_header_timeouts: snapshot.slow_attack_header_timeouts,
        slow_attack_body_timeouts: snapshot.slow_attack_body_timeouts,
        slow_attack_tls_handshake_hits: snapshot.slow_attack_tls_handshake_hits,
        slow_attack_blocks: snapshot.slow_attack_blocks,
        upstream_healthcheck_successes: snapshot.upstream_healthcheck_successes,
        upstream_healthcheck_failures: snapshot.upstream_healthcheck_failures,
        proxy_latency_micros_total: snapshot.proxy_latency_micros_total,
        average_proxy_latency_micros: snapshot.average_proxy_latency_micros,
        active_rules,
        sqlite_enabled,
        persisted_security_events: storage_summary.security_events,
        persisted_blocked_ips: storage_summary.blocked_ips,
        persisted_rules: storage_summary.rules,
        sqlite_queue_capacity: storage_summary.queue_capacity,
        sqlite_queue_depth: storage_summary.queue_depth,
        sqlite_dropped_security_events: storage_summary.dropped_security_events,
        sqlite_dropped_blocked_ips: storage_summary.dropped_blocked_ips,
        last_persisted_event_at: storage_summary.latest_event_at,
        last_rule_update_at: storage_summary.latest_rule_update_at,
        l4_bucket_count: l4_behavior.bucket_count,
        l4_fine_grained_buckets: l4_behavior.fine_grained_buckets,
        l4_coarse_buckets: l4_behavior.coarse_buckets,
        l4_peer_only_buckets: l4_behavior.peer_only_buckets,
        l4_high_risk_buckets: l4_behavior.high_risk_buckets,
        l4_behavior_dropped_events: l4_behavior.dropped_events,
        l4_overload_level: match l4_behavior.overload_level {
            crate::l4::behavior::L4OverloadLevel::Normal => "normal".to_string(),
            crate::l4::behavior::L4OverloadLevel::High => "high".to_string(),
            crate::l4::behavior::L4OverloadLevel::Critical => "critical".to_string(),
        },
        runtime_pressure_level: runtime_pressure.level.to_string(),
        runtime_pressure_drop_delay: runtime_pressure.drop_delay,
        runtime_pressure_trim_event_persistence: runtime_pressure.trim_event_persistence,
        runtime_pressure_storage_queue_percent: runtime_pressure.storage_queue_usage_percent,
        storage_degraded_reasons,
        storage_attack_insights: StorageAttackInsightsResponse {
            active_bucket_count: aggregation_insights.active_bucket_count,
            active_event_count: aggregation_insights.active_event_count,
            long_tail_bucket_count: aggregation_insights.long_tail_bucket_count,
            long_tail_event_count: aggregation_insights.long_tail_event_count,
            hotspot_sources: aggregation_insights
                .hotspot_sources
                .into_iter()
                .map(|item| StorageAttackHotspotResponse {
                    source_ip: item.source_ip,
                    action: item.action,
                    route: item.route,
                    count: item.count,
                    time_window_start: item.time_window_start,
                    time_window_end: item.time_window_end,
                })
                .collect(),
        },
    }
}

fn build_storage_degraded_reasons(
    storage_summary: &crate::storage::StorageMetricsSummary,
    aggregation_insights: &crate::storage::StorageAggregationInsightSummary,
    runtime_pressure: &RuntimePressureSnapshot,
) -> Vec<String> {
    let mut reasons = Vec::new();
    if runtime_pressure.trim_event_persistence {
        reasons.push("storage_low_value_event_persistence_trimmed".to_string());
    }
    if storage_summary.dropped_security_events > 0 {
        reasons.push("storage_security_events_dropped_under_pressure".to_string());
    }
    if aggregation_insights.long_tail_event_count > 0 {
        reasons.push("storage_long_tail_sources_merged".to_string());
    }
    if aggregation_insights.active_bucket_count > 0 {
        reasons.push("storage_hotspot_aggregation_active".to_string());
    }
    reasons
}
