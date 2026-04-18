use crate::core::InspectionLayer;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

mod segments;
mod snapshot;

pub use self::segments::ProxyTrafficSegmentSnapshot;
pub use self::snapshot::{MetricsSnapshot, ProxyTrafficMetricsSnapshot};

use self::segments::{
    host_route_segment_key, host_segment_key, route_segment_key, segment_snapshots,
    update_segment_map, ProxySegmentScope, ProxySegmentUpdate, ProxyTrafficSegmentAccumulator,
};

pub struct MetricsCollector {
    total_packets: AtomicU64,
    blocked_packets: AtomicU64,
    blocked_l4: AtomicU64,
    blocked_l7: AtomicU64,
    l7_cc_challenges: AtomicU64,
    l7_cc_blocks: AtomicU64,
    l7_cc_delays: AtomicU64,
    l7_cc_unresolved_identity_delays: AtomicU64,
    l7_cc_verified_passes: AtomicU64,
    l7_behavior_challenges: AtomicU64,
    l7_behavior_blocks: AtomicU64,
    l7_behavior_delays: AtomicU64,
    l7_ip_access_allows: AtomicU64,
    l7_ip_access_alerts: AtomicU64,
    l7_ip_access_challenges: AtomicU64,
    l7_ip_access_blocks: AtomicU64,
    l7_ip_access_verified_passes: AtomicU64,
    total_bytes: AtomicU64,
    proxied_requests: AtomicU64,
    proxy_successes: AtomicU64,
    proxy_failures: AtomicU64,
    proxy_fail_close_rejections: AtomicU64,
    l4_bucket_budget_rejections: AtomicU64,
    l4_request_budget_softened: AtomicU64,
    tls_pre_handshake_rejections: AtomicU64,
    trusted_proxy_permit_drops: AtomicU64,
    trusted_proxy_l4_degrade_actions: AtomicU64,
    tls_handshake_timeouts: AtomicU64,
    tls_handshake_failures: AtomicU64,
    slow_attack_idle_timeouts: AtomicU64,
    slow_attack_header_timeouts: AtomicU64,
    slow_attack_body_timeouts: AtomicU64,
    slow_attack_tls_handshake_hits: AtomicU64,
    slow_attack_blocks: AtomicU64,
    upstream_healthcheck_successes: AtomicU64,
    upstream_healthcheck_failures: AtomicU64,
    proxy_latency_micros_total: AtomicU64,
    document_proxy_requests: AtomicU64,
    document_proxy_successes: AtomicU64,
    document_proxy_failures: AtomicU64,
    document_proxy_latency_micros_total: AtomicU64,
    api_proxy_requests: AtomicU64,
    api_proxy_successes: AtomicU64,
    api_proxy_failures: AtomicU64,
    api_proxy_latency_micros_total: AtomicU64,
    static_proxy_requests: AtomicU64,
    static_proxy_successes: AtomicU64,
    static_proxy_failures: AtomicU64,
    static_proxy_latency_micros_total: AtomicU64,
    other_proxy_requests: AtomicU64,
    other_proxy_successes: AtomicU64,
    other_proxy_failures: AtomicU64,
    other_proxy_latency_micros_total: AtomicU64,
    host_proxy_segments: Mutex<HashMap<String, ProxyTrafficSegmentAccumulator>>,
    route_proxy_segments: Mutex<HashMap<String, ProxyTrafficSegmentAccumulator>>,
    host_route_proxy_segments: Mutex<HashMap<String, ProxyTrafficSegmentAccumulator>>,
}

#[derive(Debug, Clone, Copy)]
pub enum ProxyTrafficKind {
    Document,
    Api,
    Static,
    Other,
}

#[derive(Debug, Clone)]
pub struct ProxyMetricLabels {
    pub host: String,
    pub route: String,
    pub request_kind: String,
}

impl MetricsCollector {
    pub fn new() -> Self {
        Self {
            total_packets: AtomicU64::new(0),
            blocked_packets: AtomicU64::new(0),
            blocked_l4: AtomicU64::new(0),
            blocked_l7: AtomicU64::new(0),
            l7_cc_challenges: AtomicU64::new(0),
            l7_cc_blocks: AtomicU64::new(0),
            l7_cc_delays: AtomicU64::new(0),
            l7_cc_unresolved_identity_delays: AtomicU64::new(0),
            l7_cc_verified_passes: AtomicU64::new(0),
            l7_behavior_challenges: AtomicU64::new(0),
            l7_behavior_blocks: AtomicU64::new(0),
            l7_behavior_delays: AtomicU64::new(0),
            l7_ip_access_allows: AtomicU64::new(0),
            l7_ip_access_alerts: AtomicU64::new(0),
            l7_ip_access_challenges: AtomicU64::new(0),
            l7_ip_access_blocks: AtomicU64::new(0),
            l7_ip_access_verified_passes: AtomicU64::new(0),
            total_bytes: AtomicU64::new(0),
            proxied_requests: AtomicU64::new(0),
            proxy_successes: AtomicU64::new(0),
            proxy_failures: AtomicU64::new(0),
            proxy_fail_close_rejections: AtomicU64::new(0),
            l4_bucket_budget_rejections: AtomicU64::new(0),
            l4_request_budget_softened: AtomicU64::new(0),
            tls_pre_handshake_rejections: AtomicU64::new(0),
            trusted_proxy_permit_drops: AtomicU64::new(0),
            trusted_proxy_l4_degrade_actions: AtomicU64::new(0),
            tls_handshake_timeouts: AtomicU64::new(0),
            tls_handshake_failures: AtomicU64::new(0),
            slow_attack_idle_timeouts: AtomicU64::new(0),
            slow_attack_header_timeouts: AtomicU64::new(0),
            slow_attack_body_timeouts: AtomicU64::new(0),
            slow_attack_tls_handshake_hits: AtomicU64::new(0),
            slow_attack_blocks: AtomicU64::new(0),
            upstream_healthcheck_successes: AtomicU64::new(0),
            upstream_healthcheck_failures: AtomicU64::new(0),
            proxy_latency_micros_total: AtomicU64::new(0),
            document_proxy_requests: AtomicU64::new(0),
            document_proxy_successes: AtomicU64::new(0),
            document_proxy_failures: AtomicU64::new(0),
            document_proxy_latency_micros_total: AtomicU64::new(0),
            api_proxy_requests: AtomicU64::new(0),
            api_proxy_successes: AtomicU64::new(0),
            api_proxy_failures: AtomicU64::new(0),
            api_proxy_latency_micros_total: AtomicU64::new(0),
            static_proxy_requests: AtomicU64::new(0),
            static_proxy_successes: AtomicU64::new(0),
            static_proxy_failures: AtomicU64::new(0),
            static_proxy_latency_micros_total: AtomicU64::new(0),
            other_proxy_requests: AtomicU64::new(0),
            other_proxy_successes: AtomicU64::new(0),
            other_proxy_failures: AtomicU64::new(0),
            other_proxy_latency_micros_total: AtomicU64::new(0),
            host_proxy_segments: Mutex::new(HashMap::new()),
            route_proxy_segments: Mutex::new(HashMap::new()),
            host_route_proxy_segments: Mutex::new(HashMap::new()),
        }
    }

    pub fn record_packet(&self, bytes: usize) {
        self.total_packets.fetch_add(1, Ordering::Relaxed);
        self.total_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub fn record_block(&self, layer: InspectionLayer) {
        self.blocked_packets.fetch_add(1, Ordering::Relaxed);
        match layer {
            InspectionLayer::L4 => {
                self.blocked_l4.fetch_add(1, Ordering::Relaxed);
            }
            InspectionLayer::L7 => {
                self.blocked_l7.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub fn record_proxy_attempt(&self) {
        self.record_proxy_attempt_with_kind(ProxyTrafficKind::Other);
    }

    pub fn record_proxy_success(&self, latency: std::time::Duration) {
        self.record_proxy_success_with_kind(ProxyTrafficKind::Other, latency);
    }

    pub fn record_proxy_failure(&self) {
        self.record_proxy_failure_with_kind(ProxyTrafficKind::Other);
    }

    pub fn record_proxy_attempt_with_kind(&self, kind: ProxyTrafficKind) {
        self.proxied_requests.fetch_add(1, Ordering::Relaxed);
        self.proxy_requests_counter(kind)
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_proxy_attempt_with_labels(
        &self,
        kind: ProxyTrafficKind,
        labels: &ProxyMetricLabels,
    ) {
        self.record_proxy_attempt_with_kind(kind);
        self.update_segment_maps(
            labels,
            ProxySegmentUpdate::Attempt {
                latency_micros: None,
            },
        );
    }

    pub fn record_proxy_success_with_kind(
        &self,
        kind: ProxyTrafficKind,
        latency: std::time::Duration,
    ) {
        self.proxy_successes.fetch_add(1, Ordering::Relaxed);
        self.proxy_latency_micros_total
            .fetch_add(latency.as_micros() as u64, Ordering::Relaxed);
        self.proxy_successes_counter(kind)
            .fetch_add(1, Ordering::Relaxed);
        self.proxy_latency_counter(kind)
            .fetch_add(latency.as_micros() as u64, Ordering::Relaxed);
    }

    pub fn record_proxy_success_with_labels(
        &self,
        kind: ProxyTrafficKind,
        latency: std::time::Duration,
        labels: &ProxyMetricLabels,
    ) {
        self.record_proxy_success_with_kind(kind, latency);
        self.update_segment_maps(
            labels,
            ProxySegmentUpdate::Success {
                latency_micros: Some(latency.as_micros() as u64),
            },
        );
    }

    pub fn record_proxy_failure_with_kind(&self, kind: ProxyTrafficKind) {
        self.proxy_failures.fetch_add(1, Ordering::Relaxed);
        self.proxy_failures_counter(kind)
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_proxy_failure_with_labels(
        &self,
        kind: ProxyTrafficKind,
        labels: &ProxyMetricLabels,
    ) {
        self.record_proxy_failure_with_kind(kind);
        self.update_segment_maps(
            labels,
            ProxySegmentUpdate::Failure {
                latency_micros: None,
            },
        );
    }

    pub fn record_fail_close_rejection(&self) {
        self.proxy_fail_close_rejections
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_l4_bucket_budget_rejection(&self) {
        self.l4_bucket_budget_rejections
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_l4_request_budget_softened(&self) {
        self.l4_request_budget_softened
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_tls_pre_handshake_rejection(&self) {
        self.tls_pre_handshake_rejections
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_trusted_proxy_permit_drop(&self) {
        self.trusted_proxy_permit_drops
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_trusted_proxy_l4_degrade_action(&self) {
        self.trusted_proxy_l4_degrade_actions
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_tls_handshake_timeout(&self) {
        self.tls_handshake_timeouts.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_tls_handshake_failure(&self) {
        self.tls_handshake_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_slow_attack_idle_timeout(&self) {
        self.slow_attack_idle_timeouts
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_slow_attack_header_timeout(&self) {
        self.slow_attack_header_timeouts
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_slow_attack_body_timeout(&self) {
        self.slow_attack_body_timeouts
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_slow_attack_tls_handshake(&self) {
        self.slow_attack_tls_handshake_hits
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_slow_attack_block(&self) {
        self.slow_attack_blocks.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_l7_cc_challenge(&self) {
        self.l7_cc_challenges.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_l7_cc_block(&self) {
        self.l7_cc_blocks.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_l7_cc_delay(&self) {
        self.l7_cc_delays.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_l7_cc_unresolved_identity_delay(&self) {
        self.l7_cc_unresolved_identity_delays
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_l7_cc_verified_pass(&self) {
        self.l7_cc_verified_passes.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_l7_behavior_challenge(&self) {
        self.l7_behavior_challenges.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_l7_behavior_block(&self) {
        self.l7_behavior_blocks.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_l7_behavior_delay(&self) {
        self.l7_behavior_delays.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_l7_ip_access_allow(&self) {
        self.l7_ip_access_allows.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_l7_ip_access_alert(&self) {
        self.l7_ip_access_alerts.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_l7_ip_access_challenge(&self) {
        self.l7_ip_access_challenges.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_l7_ip_access_block(&self) {
        self.l7_ip_access_blocks.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_l7_ip_access_verified_pass(&self) {
        self.l7_ip_access_verified_passes
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_upstream_healthcheck(&self, healthy: bool) {
        if healthy {
            self.upstream_healthcheck_successes
                .fetch_add(1, Ordering::Relaxed);
        } else {
            self.upstream_healthcheck_failures
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    fn proxy_requests_counter(&self, kind: ProxyTrafficKind) -> &AtomicU64 {
        match kind {
            ProxyTrafficKind::Document => &self.document_proxy_requests,
            ProxyTrafficKind::Api => &self.api_proxy_requests,
            ProxyTrafficKind::Static => &self.static_proxy_requests,
            ProxyTrafficKind::Other => &self.other_proxy_requests,
        }
    }

    fn proxy_successes_counter(&self, kind: ProxyTrafficKind) -> &AtomicU64 {
        match kind {
            ProxyTrafficKind::Document => &self.document_proxy_successes,
            ProxyTrafficKind::Api => &self.api_proxy_successes,
            ProxyTrafficKind::Static => &self.static_proxy_successes,
            ProxyTrafficKind::Other => &self.other_proxy_successes,
        }
    }

    fn proxy_failures_counter(&self, kind: ProxyTrafficKind) -> &AtomicU64 {
        match kind {
            ProxyTrafficKind::Document => &self.document_proxy_failures,
            ProxyTrafficKind::Api => &self.api_proxy_failures,
            ProxyTrafficKind::Static => &self.static_proxy_failures,
            ProxyTrafficKind::Other => &self.other_proxy_failures,
        }
    }

    fn proxy_latency_counter(&self, kind: ProxyTrafficKind) -> &AtomicU64 {
        match kind {
            ProxyTrafficKind::Document => &self.document_proxy_latency_micros_total,
            ProxyTrafficKind::Api => &self.api_proxy_latency_micros_total,
            ProxyTrafficKind::Static => &self.static_proxy_latency_micros_total,
            ProxyTrafficKind::Other => &self.other_proxy_latency_micros_total,
        }
    }

    pub fn get_stats(&self) -> MetricsSnapshot {
        let proxy_successes = self.proxy_successes.load(Ordering::Relaxed);
        let proxy_latency_micros_total = self.proxy_latency_micros_total.load(Ordering::Relaxed);
        MetricsSnapshot {
            total_packets: self.total_packets.load(Ordering::Relaxed),
            blocked_packets: self.blocked_packets.load(Ordering::Relaxed),
            blocked_l4: self.blocked_l4.load(Ordering::Relaxed),
            blocked_l7: self.blocked_l7.load(Ordering::Relaxed),
            l7_cc_challenges: self.l7_cc_challenges.load(Ordering::Relaxed),
            l7_cc_blocks: self.l7_cc_blocks.load(Ordering::Relaxed),
            l7_cc_delays: self.l7_cc_delays.load(Ordering::Relaxed),
            l7_cc_unresolved_identity_delays: self
                .l7_cc_unresolved_identity_delays
                .load(Ordering::Relaxed),
            l7_cc_verified_passes: self.l7_cc_verified_passes.load(Ordering::Relaxed),
            l7_behavior_challenges: self.l7_behavior_challenges.load(Ordering::Relaxed),
            l7_behavior_blocks: self.l7_behavior_blocks.load(Ordering::Relaxed),
            l7_behavior_delays: self.l7_behavior_delays.load(Ordering::Relaxed),
            l7_ip_access_allows: self.l7_ip_access_allows.load(Ordering::Relaxed),
            l7_ip_access_alerts: self.l7_ip_access_alerts.load(Ordering::Relaxed),
            l7_ip_access_challenges: self.l7_ip_access_challenges.load(Ordering::Relaxed),
            l7_ip_access_blocks: self.l7_ip_access_blocks.load(Ordering::Relaxed),
            l7_ip_access_verified_passes: self.l7_ip_access_verified_passes.load(Ordering::Relaxed),
            total_bytes: self.total_bytes.load(Ordering::Relaxed),
            proxied_requests: self.proxied_requests.load(Ordering::Relaxed),
            proxy_successes,
            proxy_failures: self.proxy_failures.load(Ordering::Relaxed),
            proxy_fail_close_rejections: self.proxy_fail_close_rejections.load(Ordering::Relaxed),
            l4_bucket_budget_rejections: self.l4_bucket_budget_rejections.load(Ordering::Relaxed),
            l4_request_budget_softened: self.l4_request_budget_softened.load(Ordering::Relaxed),
            tls_pre_handshake_rejections: self.tls_pre_handshake_rejections.load(Ordering::Relaxed),
            trusted_proxy_permit_drops: self.trusted_proxy_permit_drops.load(Ordering::Relaxed),
            trusted_proxy_l4_degrade_actions: self
                .trusted_proxy_l4_degrade_actions
                .load(Ordering::Relaxed),
            tls_handshake_timeouts: self.tls_handshake_timeouts.load(Ordering::Relaxed),
            tls_handshake_failures: self.tls_handshake_failures.load(Ordering::Relaxed),
            slow_attack_idle_timeouts: self.slow_attack_idle_timeouts.load(Ordering::Relaxed),
            slow_attack_header_timeouts: self.slow_attack_header_timeouts.load(Ordering::Relaxed),
            slow_attack_body_timeouts: self.slow_attack_body_timeouts.load(Ordering::Relaxed),
            slow_attack_tls_handshake_hits: self
                .slow_attack_tls_handshake_hits
                .load(Ordering::Relaxed),
            slow_attack_blocks: self.slow_attack_blocks.load(Ordering::Relaxed),
            upstream_healthcheck_successes: self
                .upstream_healthcheck_successes
                .load(Ordering::Relaxed),
            upstream_healthcheck_failures: self
                .upstream_healthcheck_failures
                .load(Ordering::Relaxed),
            proxy_latency_micros_total,
            average_proxy_latency_micros: if proxy_successes == 0 {
                0
            } else {
                proxy_latency_micros_total / proxy_successes
            },
            document_proxy: self.proxy_traffic_snapshot(ProxyTrafficKind::Document),
            api_proxy: self.proxy_traffic_snapshot(ProxyTrafficKind::Api),
            static_proxy: self.proxy_traffic_snapshot(ProxyTrafficKind::Static),
            other_proxy: self.proxy_traffic_snapshot(ProxyTrafficKind::Other),
            top_host_segments: segment_snapshots(
                &self.host_proxy_segments,
                ProxySegmentScope::Host,
                5,
            ),
            top_route_segments: segment_snapshots(
                &self.route_proxy_segments,
                ProxySegmentScope::Route,
                5,
            ),
            top_host_route_segments: segment_snapshots(
                &self.host_route_proxy_segments,
                ProxySegmentScope::HostRoute,
                5,
            ),
            l4_direct_idle_no_request_buckets: 0,
            l4_direct_idle_no_request_connections: 0,
        }
    }

    fn proxy_traffic_snapshot(&self, kind: ProxyTrafficKind) -> ProxyTrafficMetricsSnapshot {
        let requests = self.proxy_requests_counter(kind).load(Ordering::Relaxed);
        let successes = self.proxy_successes_counter(kind).load(Ordering::Relaxed);
        let failures = self.proxy_failures_counter(kind).load(Ordering::Relaxed);
        let latency_micros_total = self.proxy_latency_counter(kind).load(Ordering::Relaxed);
        ProxyTrafficMetricsSnapshot {
            proxied_requests: requests,
            proxy_successes: successes,
            proxy_failures: failures,
            average_proxy_latency_micros: if successes == 0 {
                0
            } else {
                latency_micros_total / successes
            },
        }
    }

    fn update_segment_maps(&self, labels: &ProxyMetricLabels, update: ProxySegmentUpdate) {
        update_segment_map(&self.host_proxy_segments, host_segment_key(labels), update);
        update_segment_map(
            &self.route_proxy_segments,
            route_segment_key(labels),
            update,
        );
        update_segment_map(
            &self.host_route_proxy_segments,
            host_route_segment_key(labels),
            update,
        );
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_snapshot_includes_proxy_counters() {
        let metrics = MetricsCollector::new();
        metrics.record_packet(128);
        metrics.record_proxy_attempt();
        metrics.record_proxy_success(std::time::Duration::from_millis(4));
        metrics.record_proxy_failure();
        metrics.record_fail_close_rejection();
        metrics.record_l4_request_budget_softened();
        metrics.record_tls_pre_handshake_rejection();
        metrics.record_tls_handshake_timeout();
        metrics.record_tls_handshake_failure();
        metrics.record_l7_cc_challenge();
        metrics.record_l7_cc_block();
        metrics.record_l7_cc_delay();
        metrics.record_l7_cc_unresolved_identity_delay();
        metrics.record_l7_cc_verified_pass();
        metrics.record_l7_ip_access_allow();
        metrics.record_l7_ip_access_alert();
        metrics.record_l7_ip_access_challenge();
        metrics.record_l7_ip_access_block();
        metrics.record_l7_ip_access_verified_pass();
        metrics.record_upstream_healthcheck(true);
        metrics.record_upstream_healthcheck(false);
        metrics.record_trusted_proxy_permit_drop();
        metrics.record_trusted_proxy_l4_degrade_action();

        let snapshot = metrics.get_stats();
        assert_eq!(snapshot.total_packets, 1);
        assert_eq!(snapshot.l7_cc_challenges, 1);
        assert_eq!(snapshot.l7_cc_blocks, 1);
        assert_eq!(snapshot.l7_cc_delays, 1);
        assert_eq!(snapshot.l7_cc_unresolved_identity_delays, 1);
        assert_eq!(snapshot.l7_cc_verified_passes, 1);
        assert_eq!(snapshot.l7_ip_access_allows, 1);
        assert_eq!(snapshot.l7_ip_access_alerts, 1);
        assert_eq!(snapshot.l7_ip_access_challenges, 1);
        assert_eq!(snapshot.l7_ip_access_blocks, 1);
        assert_eq!(snapshot.l7_ip_access_verified_passes, 1);
        assert_eq!(snapshot.proxied_requests, 1);
        assert_eq!(snapshot.proxy_successes, 1);
        assert_eq!(snapshot.proxy_failures, 1);
        assert_eq!(snapshot.proxy_fail_close_rejections, 1);
        assert_eq!(snapshot.l4_bucket_budget_rejections, 0);
        assert_eq!(snapshot.l4_request_budget_softened, 1);
        assert_eq!(snapshot.tls_pre_handshake_rejections, 1);
        assert_eq!(snapshot.trusted_proxy_permit_drops, 1);
        assert_eq!(snapshot.trusted_proxy_l4_degrade_actions, 1);
        assert_eq!(snapshot.tls_handshake_timeouts, 1);
        assert_eq!(snapshot.tls_handshake_failures, 1);
        assert_eq!(snapshot.upstream_healthcheck_successes, 1);
        assert_eq!(snapshot.upstream_healthcheck_failures, 1);
        assert_eq!(snapshot.proxy_latency_micros_total, 4_000);
        assert_eq!(snapshot.average_proxy_latency_micros, 4_000);
        assert_eq!(snapshot.other_proxy.proxied_requests, 1);
        assert_eq!(snapshot.other_proxy.proxy_successes, 1);
        assert_eq!(snapshot.other_proxy.proxy_failures, 1);
        assert_eq!(snapshot.other_proxy.average_proxy_latency_micros, 4_000);
    }
}
