use crate::config::L4Config;
use crate::core::PacketInfo;
use crate::protocol::{HttpVersion, UnifiedHttpRequest};
use dashmap::DashMap;
use serde::Serialize;
use std::collections::VecDeque;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::{Mutex, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

mod engine;
mod policy;
mod runtime;

const CONNECTION_WINDOW: Duration = Duration::from_secs(10);
const REQUEST_WINDOW: Duration = Duration::from_secs(10);
const FEEDBACK_WINDOW: Duration = Duration::from_secs(120);
const COOL_DOWN_SECS: i64 = 10;

#[derive(Debug)]
pub struct L4BehaviorEngine {
    buckets: Arc<DashMap<BucketKey, BucketRuntime>>,
    sender: mpsc::Sender<BehaviorEvent>,
    worker_receiver: Mutex<Option<mpsc::Receiver<BehaviorEvent>>>,
    dropped_events: Arc<AtomicU64>,
    max_buckets: usize,
    fallback_threshold: usize,
    tuning: Arc<RwLock<L4BehaviorTuning>>,
}

#[derive(Debug, Clone)]
struct L4BehaviorTuning {
    event_drop_critical_threshold: u64,
    overload_blocked_connections_threshold: u64,
    overload_active_connections_threshold: u64,
    normal_connection_budget_per_minute: u32,
    suspicious_connection_budget_per_minute: u32,
    high_risk_connection_budget_per_minute: u32,
    high_overload_budget_scale_percent: u8,
    critical_overload_budget_scale_percent: u8,
    high_overload_delay_ms: u64,
    critical_overload_delay_ms: u64,
    soft_delay_threshold_percent: u16,
    hard_delay_threshold_percent: u16,
    soft_delay_ms: u64,
    hard_delay_ms: u64,
    reject_threshold_percent: u16,
    critical_reject_threshold_percent: u16,
}

#[derive(Debug)]
enum BehaviorEvent {
    ConnectionOpened {
        key: BucketKey,
        connection_id: String,
        now: Instant,
        unix_now: i64,
    },
    ConnectionClosed {
        key: BucketKey,
        connection_id: String,
        duration_ms: u64,
        now: Instant,
        unix_now: i64,
    },
    RequestObserved {
        key: BucketKey,
        bytes: u64,
        now: Instant,
        unix_now: i64,
    },
    Feedback {
        key: BucketKey,
        source: FeedbackSource,
        now: Instant,
        unix_now: i64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BucketKey {
    pub peer_ip: IpAddr,
    pub peer_kind: BucketPeerKind,
    pub authority: String,
    pub alpn: BucketAlpn,
    pub transport: BucketTransport,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BucketPeerKind {
    DirectClient,
    TrustedProxy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BucketAlpn {
    Http11,
    H2,
    H3,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BucketTransport {
    Http,
    Tls,
    Udp,
    Unknown,
}

#[derive(Debug, Clone)]
struct BucketRuntime {
    peer_kind: BucketPeerKind,
    last_seen_at: i64,
    last_seen_instant: Instant,
    state_since: i64,
    recent_connections: VecDeque<Instant>,
    recent_requests: VecDeque<Instant>,
    recent_feedback: VecDeque<Instant>,
    active_connections: u32,
    total_connections: u64,
    total_requests: u64,
    total_bytes: u64,
    l7_block_hits: u64,
    safeline_hits: u64,
    slow_attack_hits: u64,
    avg_connection_lifetime_ms: f64,
    score_ewma: f64,
    risk_level: L4BucketRiskLevel,
    cooldown_until: i64,
    protocol_hint: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum L4BucketRiskLevel {
    Normal,
    Suspicious,
    High,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum L4OverloadLevel {
    Normal,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize)]
pub struct L4BucketPolicySnapshot {
    pub connection_budget_per_minute: u32,
    pub shrink_idle_timeout: bool,
    pub disable_keepalive: bool,
    pub prefer_early_close: bool,
    pub reject_new_connections: bool,
    pub mode: String,
    pub suggested_delay_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct L4BucketSnapshot {
    pub peer_ip: String,
    pub peer_kind: BucketPeerKind,
    pub authority: String,
    pub alpn: BucketAlpn,
    pub transport: BucketTransport,
    pub protocol_hint: String,
    pub total_connections: u64,
    pub total_requests: u64,
    pub total_bytes: u64,
    pub recent_connections_10s: u64,
    pub recent_requests_10s: u64,
    pub recent_feedback_120s: u64,
    pub active_connections: u32,
    pub requests_per_connection: f64,
    pub avg_connection_lifetime_ms: u64,
    pub l7_block_hits: u64,
    pub safeline_hits: u64,
    pub slow_attack_hits: u64,
    pub risk_score: u32,
    pub risk_level: L4BucketRiskLevel,
    pub policy: L4BucketPolicySnapshot,
    pub last_seen_at: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct L4BehaviorOverview {
    pub bucket_count: u64,
    pub fine_grained_buckets: u64,
    pub coarse_buckets: u64,
    pub peer_only_buckets: u64,
    pub direct_idle_no_request_buckets: u64,
    pub direct_idle_no_request_connections: u64,
    pub normal_buckets: u64,
    pub suspicious_buckets: u64,
    pub high_risk_buckets: u64,
    pub safeline_feedback_hits: u64,
    pub l7_feedback_hits: u64,
    pub dropped_events: u64,
    pub overload_level: L4OverloadLevel,
    pub overload_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct L4BehaviorSnapshot {
    pub overview: L4BehaviorOverview,
    pub top_buckets: Vec<L4BucketSnapshot>,
}

#[derive(Debug, Clone)]
pub struct L4AdaptivePolicy {
    pub risk_level: L4BucketRiskLevel,
    pub risk_score: u32,
    pub disable_keepalive: bool,
    pub prefer_early_close: bool,
    pub reject_new_connections: bool,
    pub connection_budget_per_minute: u32,
    pub suggested_delay_ms: u64,
}

#[derive(Debug, Clone, Copy)]
pub enum FeedbackSource {
    L7Block,
    SafeLine,
    SlowAttack,
}

impl L4BehaviorTuning {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::L4Config;
    use crate::core::{PacketInfo, Protocol};
    use std::net::{IpAddr, Ipv4Addr};
    use tokio::time::{sleep, Duration};

    fn packet(ip: u8) -> PacketInfo {
        PacketInfo {
            source_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, ip)),
            dest_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            source_port: 40000,
            dest_port: 443,
            protocol: Protocol::TCP,
            timestamp: 1,
        }
    }

    #[tokio::test]
    async fn pre_admission_uses_peer_transport_fallback() {
        let engine = L4BehaviorEngine::new(&L4Config {
            max_tracked_ips: 4,
            ..L4Config::default()
        });
        engine.start();
        let peer_ip = packet(10).source_ip;

        for idx in 0..160 {
            let p = PacketInfo {
                timestamp: idx,
                ..packet(10)
            };
            let _ = engine.observe_connection_open(
                format!("conn-{idx}"),
                &p,
                Some("example.com"),
                Some("h2"),
                "tls",
                "h2",
                BucketPeerKind::DirectClient,
            );
        }

        sleep(Duration::from_millis(50)).await;
        let policy = engine.pre_admission_policy(peer_ip, "tls");
        assert!(policy.suggested_delay_ms > 0 || policy.reject_new_connections);
    }

    #[tokio::test]
    async fn snapshot_reports_coarse_and_peer_only_buckets() {
        let engine = L4BehaviorEngine::new(&L4Config {
            max_tracked_ips: 3,
            ..L4Config::default()
        });
        engine.start();

        let p1 = packet(11);
        let p2 = packet(12);
        let p3 = packet(13);

        let _ = engine.observe_connection_open(
            "a".to_string(),
            &p1,
            Some("a.example"),
            Some("h2"),
            "tls",
            "h2",
            BucketPeerKind::DirectClient,
        );
        let _ = engine.observe_connection_open(
            "b".to_string(),
            &p2,
            Some("b.example"),
            None,
            "http",
            "http/1.1",
            BucketPeerKind::DirectClient,
        );
        let _ = engine.observe_connection_open(
            "c".to_string(),
            &p3,
            None,
            None,
            "tcp",
            "unknown",
            BucketPeerKind::DirectClient,
        );

        sleep(Duration::from_millis(50)).await;
        let snapshot = engine.snapshot(0, 0);
        assert!(snapshot.overview.bucket_count >= 1);
        assert!(
            snapshot.overview.fine_grained_buckets
                + snapshot.overview.coarse_buckets
                + snapshot.overview.peer_only_buckets
                >= 1
        );
    }

    #[tokio::test]
    async fn connection_admission_reacts_to_active_connection_pressure() {
        let engine = L4BehaviorEngine::new(&L4Config {
            max_tracked_ips: 16,
            ..L4Config::default()
        });
        engine.start();
        let p = packet(21);
        let mut key = None;

        for idx in 0..220 {
            key = Some(engine.observe_connection_open(
                format!("active-{idx}"),
                &PacketInfo {
                    timestamp: idx,
                    ..p.clone()
                },
                Some("busy.example"),
                Some("h2"),
                "tls",
                "h2",
                BucketPeerKind::DirectClient,
            ));
        }

        sleep(Duration::from_millis(50)).await;
        let policy = engine.connection_admission_for_key(&key.expect("bucket key"));
        assert!(policy.suggested_delay_ms > 0 || policy.reject_new_connections);
    }

    #[tokio::test]
    async fn default_policy_uses_configured_budget() {
        let engine = L4BehaviorEngine::new(&L4Config {
            behavior_normal_connection_budget_per_minute: 42,
            ..L4Config::default()
        });
        engine.start();

        let policy = engine.pre_admission_policy(packet(30).source_ip, "tls");
        assert_eq!(policy.connection_budget_per_minute, 42);
    }

    #[tokio::test]
    async fn dropped_events_remain_below_critical_until_threshold_is_hit() {
        let engine = L4BehaviorEngine::new(&L4Config {
            max_tracked_ips: 128,
            behavior_event_channel_capacity: 1,
            behavior_drop_critical_threshold: 10_000,
            ..L4Config::default()
        });
        engine.start();
        let p = packet(31);

        for idx in 0..2_000 {
            let _ = engine.observe_connection_open(
                format!("drop-{idx}"),
                &PacketInfo {
                    timestamp: idx,
                    ..p.clone()
                },
                Some("drop.example"),
                Some("h2"),
                "tls",
                "h2",
                BucketPeerKind::DirectClient,
            );
        }

        sleep(Duration::from_millis(50)).await;
        let snapshot = engine.snapshot(0, 0);
        assert!(snapshot.overview.dropped_events > 0);
        assert_ne!(snapshot.overview.overload_level, L4OverloadLevel::Critical);
    }

    #[tokio::test]
    async fn trusted_proxy_connections_degrade_without_rejecting() {
        let engine = L4BehaviorEngine::new(&L4Config {
            max_tracked_ips: 16,
            behavior_normal_connection_budget_per_minute: 24,
            behavior_suspicious_connection_budget_per_minute: 12,
            behavior_high_risk_connection_budget_per_minute: 6,
            ..L4Config::default()
        });
        engine.start();
        let p = packet(41);
        let mut key = None;

        for idx in 0..240 {
            key = Some(engine.observe_connection_open(
                format!("proxy-{idx}"),
                &PacketInfo {
                    timestamp: idx,
                    ..p.clone()
                },
                Some("cdn.example"),
                Some("h2"),
                "tls",
                "h2",
                BucketPeerKind::TrustedProxy,
            ));
        }

        sleep(Duration::from_millis(50)).await;
        let policy = engine.connection_admission_for_key(&key.expect("bucket key"));
        assert!(policy.suggested_delay_ms > 0 || policy.disable_keepalive);
        assert!(policy.disable_keepalive);
        assert!(policy.prefer_early_close);
        assert!(!policy.reject_new_connections);
    }

    #[tokio::test]
    async fn unresolved_cdn_identity_forces_degrade_without_immediate_reject() {
        let engine = L4BehaviorEngine::new(&L4Config::default());
        let mut request =
            UnifiedHttpRequest::new(HttpVersion::Http1_1, "GET".to_string(), "/".to_string());
        request.set_client_ip("198.51.100.10".to_string());
        request.add_metadata(
            "network.identity_state".to_string(),
            "trusted_cdn_unresolved".to_string(),
        );

        let policy = engine.apply_request_policy(&packet(42), &mut request);

        assert!(policy.disable_keepalive);
        assert!(policy.prefer_early_close);
        assert!(policy.suggested_delay_ms > 0);
        assert!(!policy.reject_new_connections);
    }

    #[tokio::test]
    async fn spoofed_forward_header_identity_is_rejected_aggressively() {
        let engine = L4BehaviorEngine::new(&L4Config::default());
        let mut request =
            UnifiedHttpRequest::new(HttpVersion::Http1_1, "GET".to_string(), "/".to_string());
        request.set_client_ip("198.51.100.10".to_string());
        request.add_metadata(
            "network.identity_state".to_string(),
            "spoofed_forward_header".to_string(),
        );

        let policy = engine.apply_request_policy(&packet(43), &mut request);

        assert!(policy.disable_keepalive);
        assert!(policy.prefer_early_close);
        assert!(policy.reject_new_connections);
        assert!(policy.suggested_delay_ms >= 60);
    }

    #[tokio::test]
    async fn trusted_forwarded_requests_merge_peer_budget_pressure() {
        let engine = L4BehaviorEngine::new(&L4Config::default());
        engine.start();

        let peer_packet = packet(55);
        for idx in 0..220 {
            let _ = engine.observe_connection_open(
                format!("proxy-{idx}"),
                &peer_packet,
                Some("example.com"),
                Some("h2"),
                "tls",
                "h2",
                BucketPeerKind::TrustedProxy,
            );
        }

        sleep(Duration::from_millis(50)).await;

        let mut request =
            UnifiedHttpRequest::new(HttpVersion::Http2_0, "GET".to_string(), "/hot".to_string());
        request.add_header("host".to_string(), "example.com".to_string());
        request.set_client_ip(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 77)).to_string());
        request.add_metadata(
            "network.identity_state".to_string(),
            "trusted_cdn_forwarded".to_string(),
        );
        request.add_metadata(
            "network.client_ip_source".to_string(),
            "forwarded_header".to_string(),
        );
        request.add_metadata(
            "network.peer_ip".to_string(),
            peer_packet.source_ip.to_string(),
        );
        request.add_metadata("transport".to_string(), "tls".to_string());
        request.add_metadata("tls.alpn".to_string(), "h2".to_string());

        let policy = engine.apply_request_policy(&peer_packet, &mut request);

        assert_eq!(
            request
                .get_metadata("l4.dual_identity_budget")
                .map(String::as_str),
            Some("true")
        );
        assert_eq!(
            request
                .get_metadata("l4.peer_bucket_ip")
                .map(String::as_str),
            Some("203.0.113.55")
        );
        assert!(policy.disable_keepalive || policy.suggested_delay_ms > 0);
    }

    #[tokio::test]
    async fn direct_client_idle_connections_without_requests_escalate_risk() {
        let engine = L4BehaviorEngine::new(&L4Config::default());
        engine.start();
        let p = packet(44);

        for idx in 0..4 {
            let _ = engine.observe_connection_open(
                format!("idle-{idx}"),
                &PacketInfo {
                    timestamp: idx,
                    ..p.clone()
                },
                Some("idle.example"),
                Some("h2"),
                "tls",
                "h2",
                BucketPeerKind::DirectClient,
            );
        }

        sleep(Duration::from_millis(20)).await;
        let snapshot = engine.snapshot(0, 0);
        let bucket = snapshot
            .top_buckets
            .into_iter()
            .find(|item| item.peer_ip == p.source_ip.to_string())
            .expect("bucket snapshot");

        assert!(bucket.active_connections >= 4);
        assert_eq!(bucket.total_requests, 0);
        assert!(bucket.risk_score >= 10);
    }
}
