use super::types::MetricsResponse;

pub(super) fn build_metrics_response(
    metrics: Option<crate::metrics::MetricsSnapshot>,
    active_rules: u64,
    storage_summary: Option<crate::storage::StorageMetricsSummary>,
) -> MetricsResponse {
    let snapshot = metrics.unwrap_or(crate::metrics::MetricsSnapshot {
        total_packets: 0,
        blocked_packets: 0,
        blocked_l4: 0,
        blocked_l7: 0,
        total_bytes: 0,
        proxied_requests: 0,
        proxy_successes: 0,
        proxy_failures: 0,
        proxy_fail_close_rejections: 0,
        upstream_healthcheck_successes: 0,
        upstream_healthcheck_failures: 0,
        proxy_latency_micros_total: 0,
        average_proxy_latency_micros: 0,
    });
    let sqlite_enabled = storage_summary.is_some();
    let storage_summary = storage_summary.unwrap_or_default();

    MetricsResponse {
        total_packets: snapshot.total_packets,
        blocked_packets: snapshot.blocked_packets,
        blocked_l4: snapshot.blocked_l4,
        blocked_l7: snapshot.blocked_l7,
        total_bytes: snapshot.total_bytes,
        proxied_requests: snapshot.proxied_requests,
        proxy_successes: snapshot.proxy_successes,
        proxy_failures: snapshot.proxy_failures,
        proxy_fail_close_rejections: snapshot.proxy_fail_close_rejections,
        upstream_healthcheck_successes: snapshot.upstream_healthcheck_successes,
        upstream_healthcheck_failures: snapshot.upstream_healthcheck_failures,
        proxy_latency_micros_total: snapshot.proxy_latency_micros_total,
        average_proxy_latency_micros: snapshot.average_proxy_latency_micros,
        active_rules,
        sqlite_enabled,
        persisted_security_events: storage_summary.security_events,
        persisted_blocked_ips: storage_summary.blocked_ips,
        persisted_rules: storage_summary.rules,
        last_persisted_event_at: storage_summary.latest_event_at,
        last_rule_update_at: storage_summary.latest_rule_update_at,
    }
}
