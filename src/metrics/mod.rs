use crate::core::InspectionLayer;
use std::sync::atomic::{AtomicU64, Ordering};

pub struct MetricsCollector {
    total_packets: AtomicU64,
    blocked_packets: AtomicU64,
    blocked_l4: AtomicU64,
    blocked_l7: AtomicU64,
    total_bytes: AtomicU64,
    proxied_requests: AtomicU64,
    proxy_successes: AtomicU64,
    proxy_failures: AtomicU64,
    proxy_fail_close_rejections: AtomicU64,
    upstream_healthcheck_successes: AtomicU64,
    upstream_healthcheck_failures: AtomicU64,
    proxy_latency_micros_total: AtomicU64,
}

impl MetricsCollector {
    pub fn new() -> Self {
        Self {
            total_packets: AtomicU64::new(0),
            blocked_packets: AtomicU64::new(0),
            blocked_l4: AtomicU64::new(0),
            blocked_l7: AtomicU64::new(0),
            total_bytes: AtomicU64::new(0),
            proxied_requests: AtomicU64::new(0),
            proxy_successes: AtomicU64::new(0),
            proxy_failures: AtomicU64::new(0),
            proxy_fail_close_rejections: AtomicU64::new(0),
            upstream_healthcheck_successes: AtomicU64::new(0),
            upstream_healthcheck_failures: AtomicU64::new(0),
            proxy_latency_micros_total: AtomicU64::new(0),
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
        self.proxied_requests.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_proxy_success(&self, latency: std::time::Duration) {
        self.proxy_successes.fetch_add(1, Ordering::Relaxed);
        self.proxy_latency_micros_total
            .fetch_add(latency.as_micros() as u64, Ordering::Relaxed);
    }

    pub fn record_proxy_failure(&self) {
        self.proxy_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_fail_close_rejection(&self) {
        self.proxy_fail_close_rejections
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

    pub fn get_stats(&self) -> MetricsSnapshot {
        let proxy_successes = self.proxy_successes.load(Ordering::Relaxed);
        let proxy_latency_micros_total =
            self.proxy_latency_micros_total.load(Ordering::Relaxed);
        MetricsSnapshot {
            total_packets: self.total_packets.load(Ordering::Relaxed),
            blocked_packets: self.blocked_packets.load(Ordering::Relaxed),
            blocked_l4: self.blocked_l4.load(Ordering::Relaxed),
            blocked_l7: self.blocked_l7.load(Ordering::Relaxed),
            total_bytes: self.total_bytes.load(Ordering::Relaxed),
            proxied_requests: self.proxied_requests.load(Ordering::Relaxed),
            proxy_successes,
            proxy_failures: self.proxy_failures.load(Ordering::Relaxed),
            proxy_fail_close_rejections: self
                .proxy_fail_close_rejections
                .load(Ordering::Relaxed),
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
        }
    }
}

#[derive(Debug, Clone)]
pub struct MetricsSnapshot {
    pub total_packets: u64,
    pub blocked_packets: u64,
    pub blocked_l4: u64,
    pub blocked_l7: u64,
    pub total_bytes: u64,
    pub proxied_requests: u64,
    pub proxy_successes: u64,
    pub proxy_failures: u64,
    pub proxy_fail_close_rejections: u64,
    pub upstream_healthcheck_successes: u64,
    pub upstream_healthcheck_failures: u64,
    pub proxy_latency_micros_total: u64,
    pub average_proxy_latency_micros: u64,
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
        metrics.record_upstream_healthcheck(true);
        metrics.record_upstream_healthcheck(false);

        let snapshot = metrics.get_stats();
        assert_eq!(snapshot.total_packets, 1);
        assert_eq!(snapshot.proxied_requests, 1);
        assert_eq!(snapshot.proxy_successes, 1);
        assert_eq!(snapshot.proxy_failures, 1);
        assert_eq!(snapshot.proxy_fail_close_rejections, 1);
        assert_eq!(snapshot.upstream_healthcheck_successes, 1);
        assert_eq!(snapshot.upstream_healthcheck_failures, 1);
        assert_eq!(snapshot.proxy_latency_micros_total, 4_000);
        assert_eq!(snapshot.average_proxy_latency_micros, 4_000);
    }
}
