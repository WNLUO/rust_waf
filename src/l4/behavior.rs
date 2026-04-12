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
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;

const CONNECTION_WINDOW: Duration = Duration::from_secs(10);
const REQUEST_WINDOW: Duration = Duration::from_secs(10);
const FEEDBACK_WINDOW: Duration = Duration::from_secs(120);
const COOL_DOWN_SECS: i64 = 10;

#[derive(Debug, Clone)]
pub struct L4BehaviorEngine {
    buckets: Arc<DashMap<BucketKey, BucketRuntime>>,
    sender: mpsc::Sender<BehaviorEvent>,
    dropped_events: Arc<AtomicU64>,
    max_buckets: usize,
    fallback_threshold: usize,
    tuning: Arc<L4BehaviorTuning>,
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
    pub authority: String,
    pub alpn: BucketAlpn,
    pub transport: BucketTransport,
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
}

impl L4BehaviorTuning {
    fn from_config(config: &L4Config) -> Self {
        Self {
            event_drop_critical_threshold: config.behavior_drop_critical_threshold,
            overload_blocked_connections_threshold: config
                .behavior_overload_blocked_connections_threshold,
            overload_active_connections_threshold: config
                .behavior_overload_active_connections_threshold,
            normal_connection_budget_per_minute: config
                .behavior_normal_connection_budget_per_minute,
            suspicious_connection_budget_per_minute: config
                .behavior_suspicious_connection_budget_per_minute,
            high_risk_connection_budget_per_minute: config
                .behavior_high_risk_connection_budget_per_minute,
            high_overload_budget_scale_percent: config.behavior_high_overload_budget_scale_percent,
            critical_overload_budget_scale_percent: config
                .behavior_critical_overload_budget_scale_percent,
            high_overload_delay_ms: config.behavior_high_overload_delay_ms,
            critical_overload_delay_ms: config.behavior_critical_overload_delay_ms,
            soft_delay_threshold_percent: config.behavior_soft_delay_threshold_percent,
            hard_delay_threshold_percent: config.behavior_hard_delay_threshold_percent,
            soft_delay_ms: config.behavior_soft_delay_ms,
            hard_delay_ms: config.behavior_hard_delay_ms,
            reject_threshold_percent: config.behavior_reject_threshold_percent,
            critical_reject_threshold_percent: config.behavior_critical_reject_threshold_percent,
        }
    }
}

impl L4BehaviorEngine {
    pub fn new(config: &L4Config) -> Self {
        let buckets = Arc::new(DashMap::new());
        let tuning = Arc::new(L4BehaviorTuning::from_config(config));
        let (sender, receiver) = mpsc::channel(config.behavior_event_channel_capacity);
        let dropped_events = Arc::new(AtomicU64::new(0));
        let max_buckets = config.max_tracked_ips.max(128);
        let fallback_threshold =
            max_buckets.saturating_mul(config.behavior_fallback_ratio_percent as usize) / 100;

        tokio::spawn(worker_loop(
            Arc::clone(&buckets),
            receiver,
            max_buckets,
            fallback_threshold,
        ));

        Self {
            buckets,
            sender,
            dropped_events,
            max_buckets,
            fallback_threshold,
            tuning,
        }
    }

    pub fn pre_admission_policy(&self, peer_ip: IpAddr, transport: &str) -> L4AdaptivePolicy {
        let overload_level = self.current_overload_level();
        self.aggregate_for_peer_transport(peer_ip, canonicalize_transport(transport))
            .map(|bucket| {
                policy_from_runtime(&bucket, overload_level.clone(), self.tuning.as_ref())
            })
            .unwrap_or_else(|| default_policy(overload_level, self.tuning.as_ref()))
    }

    pub fn observe_connection_open(
        &self,
        connection_id: String,
        packet: &PacketInfo,
        authority: Option<&str>,
        alpn: Option<&str>,
        transport: &str,
        protocol_hint: &str,
    ) -> BucketKey {
        let key = BucketKey::from_parts(packet.source_ip, authority, alpn, transport);
        self.try_send(BehaviorEvent::ConnectionOpened {
            key: key.clone(),
            connection_id,
            now: Instant::now(),
            unix_now: unix_timestamp(),
        });
        if let Some(mut bucket) = self.buckets.get_mut(&key) {
            bucket.protocol_hint = protocol_hint.to_string();
        }
        key
    }

    pub fn observe_connection_close(
        &self,
        key: &BucketKey,
        connection_id: &str,
        opened_at: Instant,
    ) {
        self.try_send(BehaviorEvent::ConnectionClosed {
            key: key.clone(),
            connection_id: connection_id.to_string(),
            duration_ms: opened_at.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
            now: Instant::now(),
            unix_now: unix_timestamp(),
        });
    }

    pub fn apply_request_policy(
        &self,
        packet: &PacketInfo,
        request: &mut UnifiedHttpRequest,
    ) -> L4AdaptivePolicy {
        let key = BucketKey::from_request(packet.source_ip, request);
        let overload_level = self.current_overload_level();
        let policy = self
            .policy_for_key(&key, overload_level.clone())
            .unwrap_or_else(|| default_policy(overload_level.clone(), self.tuning.as_ref()));

        let bytes = request.to_inspection_string().len() as u64;
        self.try_send(BehaviorEvent::RequestObserved {
            key,
            bytes,
            now: Instant::now(),
            unix_now: unix_timestamp(),
        });

        request.add_metadata(
            "l4.bucket_risk".to_string(),
            risk_label(&policy.risk_level).to_string(),
        );
        request.add_metadata("l4.bucket_score".to_string(), policy.risk_score.to_string());
        request.add_metadata(
            "l4.overload_level".to_string(),
            match overload_level {
                L4OverloadLevel::Normal => "normal",
                L4OverloadLevel::High => "high",
                L4OverloadLevel::Critical => "critical",
            }
            .to_string(),
        );
        if policy.disable_keepalive {
            request.add_metadata("l4.force_close".to_string(), "true".to_string());
            request.add_metadata("proxy_connection_mode".to_string(), "close".to_string());
        }
        if policy.suggested_delay_ms > 0 {
            request.add_metadata(
                "l4.suggested_delay_ms".to_string(),
                policy.suggested_delay_ms.to_string(),
            );
        }

        policy
    }

    pub fn observe_feedback(
        &self,
        packet: &PacketInfo,
        request: &UnifiedHttpRequest,
        source: FeedbackSource,
    ) {
        self.try_send(BehaviorEvent::Feedback {
            key: BucketKey::from_request(packet.source_ip, request),
            source,
            now: Instant::now(),
            unix_now: unix_timestamp(),
        });
    }

    pub fn snapshot(
        &self,
        blocked_connections: u64,
        active_connections: u64,
    ) -> L4BehaviorSnapshot {
        let overload_level = derive_overload_level(
            self.buckets.len(),
            self.max_buckets,
            blocked_connections,
            active_connections,
            self.fallback_threshold,
            self.dropped_events.load(Ordering::Relaxed),
            self.tuning.as_ref(),
        );

        let mut normal_buckets = 0u64;
        let mut fine_grained_buckets = 0u64;
        let mut coarse_buckets = 0u64;
        let mut peer_only_buckets = 0u64;
        let mut suspicious_buckets = 0u64;
        let mut high_risk_buckets = 0u64;
        let mut safeline_feedback_hits = 0u64;
        let mut l7_feedback_hits = 0u64;

        let mut top_buckets = self
            .buckets
            .iter()
            .map(|entry| {
                let bucket = entry.value();
                if entry.key().authority == "*" && entry.key().transport == BucketTransport::Unknown
                {
                    peer_only_buckets += 1;
                } else if entry.key().alpn == BucketAlpn::Unknown {
                    coarse_buckets += 1;
                } else {
                    fine_grained_buckets += 1;
                }
                safeline_feedback_hits += bucket.safeline_hits;
                l7_feedback_hits += bucket.l7_block_hits;
                match bucket.risk_level {
                    L4BucketRiskLevel::Normal => normal_buckets += 1,
                    L4BucketRiskLevel::Suspicious => suspicious_buckets += 1,
                    L4BucketRiskLevel::High => high_risk_buckets += 1,
                }
                let policy =
                    policy_from_runtime(bucket, overload_level.clone(), self.tuning.as_ref());
                L4BucketSnapshot {
                    peer_ip: entry.key().peer_ip.to_string(),
                    authority: entry.key().authority.clone(),
                    alpn: entry.key().alpn,
                    transport: entry.key().transport,
                    protocol_hint: bucket.protocol_hint.clone(),
                    total_connections: bucket.total_connections,
                    total_requests: bucket.total_requests,
                    total_bytes: bucket.total_bytes,
                    recent_connections_10s: bucket.recent_connections.len() as u64,
                    recent_requests_10s: bucket.recent_requests.len() as u64,
                    recent_feedback_120s: bucket.recent_feedback.len() as u64,
                    active_connections: bucket.active_connections,
                    requests_per_connection: if bucket.total_connections == 0 {
                        0.0
                    } else {
                        bucket.total_requests as f64 / bucket.total_connections as f64
                    },
                    avg_connection_lifetime_ms: bucket.avg_connection_lifetime_ms.max(0.0) as u64,
                    l7_block_hits: bucket.l7_block_hits,
                    safeline_hits: bucket.safeline_hits,
                    risk_score: bucket.score_ewma.round().clamp(0.0, 100.0) as u32,
                    risk_level: bucket.risk_level.clone(),
                    policy: policy_snapshot(&policy),
                    last_seen_at: bucket.last_seen_at,
                }
            })
            .collect::<Vec<_>>();

        top_buckets.sort_by(|left, right| {
            right
                .risk_score
                .cmp(&left.risk_score)
                .then(right.active_connections.cmp(&left.active_connections))
                .then(right.recent_feedback_120s.cmp(&left.recent_feedback_120s))
                .then(
                    right
                        .recent_connections_10s
                        .cmp(&left.recent_connections_10s),
                )
                .then(left.authority.cmp(&right.authority))
        });
        top_buckets.truncate(12);

        L4BehaviorSnapshot {
            overview: L4BehaviorOverview {
                bucket_count: self.buckets.len() as u64,
                fine_grained_buckets,
                coarse_buckets,
                peer_only_buckets,
                normal_buckets,
                suspicious_buckets,
                high_risk_buckets,
                safeline_feedback_hits,
                l7_feedback_hits,
                dropped_events: self.dropped_events.load(Ordering::Relaxed),
                overload_level: overload_level.clone(),
                overload_reason: overload_reason(
                    overload_level,
                    blocked_connections,
                    active_connections,
                    self.buckets.len(),
                    self.max_buckets,
                ),
            },
            top_buckets,
        }
    }

    pub fn connection_admission_for_key(&self, key: &BucketKey) -> L4AdaptivePolicy {
        let overload_level = self.current_overload_level();
        self.policy_for_key(key, overload_level.clone())
            .unwrap_or_else(|| default_policy(overload_level, self.tuning.as_ref()))
    }

    fn try_send(&self, event: BehaviorEvent) {
        if self.sender.try_send(event).is_err() {
            self.dropped_events.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn policy_for_key(
        &self,
        key: &BucketKey,
        overload_level: L4OverloadLevel,
    ) -> Option<L4AdaptivePolicy> {
        self.lookup_bucket(key)
            .map(|bucket| policy_from_runtime(&bucket, overload_level, self.tuning.as_ref()))
    }

    fn lookup_bucket(&self, key: &BucketKey) -> Option<BucketRuntime> {
        self.buckets
            .get(key)
            .map(|item| item.clone())
            .or_else(|| self.buckets.get(&key.coarse()).map(|item| item.clone()))
            .or_else(|| self.buckets.get(&key.peer_only()).map(|item| item.clone()))
    }

    fn current_overload_level(&self) -> L4OverloadLevel {
        derive_overload_level(
            self.buckets.len(),
            self.max_buckets,
            0,
            0,
            self.fallback_threshold,
            self.dropped_events.load(Ordering::Relaxed),
            self.tuning.as_ref(),
        )
    }

    fn aggregate_for_peer_transport(
        &self,
        peer_ip: IpAddr,
        transport: BucketTransport,
    ) -> Option<BucketRuntime> {
        let mut aggregate: Option<BucketRuntime> = None;
        for entry in self.buckets.iter() {
            if entry.key().peer_ip != peer_ip {
                continue;
            }
            if transport != BucketTransport::Unknown && entry.key().transport != transport {
                continue;
            }
            let bucket = entry.value();
            let next = aggregate.get_or_insert_with(|| {
                BucketRuntime::new(bucket.last_seen_instant, bucket.last_seen_at)
            });
            next.last_seen_at = next.last_seen_at.max(bucket.last_seen_at);
            next.last_seen_instant = next.last_seen_instant.max(bucket.last_seen_instant);
            next.active_connections = next
                .active_connections
                .saturating_add(bucket.active_connections);
            next.total_connections = next
                .total_connections
                .saturating_add(bucket.total_connections);
            next.total_requests = next.total_requests.saturating_add(bucket.total_requests);
            next.total_bytes = next.total_bytes.saturating_add(bucket.total_bytes);
            next.l7_block_hits = next.l7_block_hits.saturating_add(bucket.l7_block_hits);
            next.safeline_hits = next.safeline_hits.saturating_add(bucket.safeline_hits);
            next.avg_connection_lifetime_ms = next
                .avg_connection_lifetime_ms
                .max(bucket.avg_connection_lifetime_ms);
            next.score_ewma = next.score_ewma.max(bucket.score_ewma);
            next.risk_level = max_risk_level(&next.risk_level, &bucket.risk_level);
            next.protocol_hint = transport_label(transport).to_string();
            extend_queue(&mut next.recent_connections, &bucket.recent_connections);
            extend_queue(&mut next.recent_requests, &bucket.recent_requests);
            extend_queue(&mut next.recent_feedback, &bucket.recent_feedback);
        }
        aggregate
    }
}

impl BucketKey {
    pub fn from_parts(
        peer_ip: IpAddr,
        authority: Option<&str>,
        alpn: Option<&str>,
        transport: &str,
    ) -> Self {
        Self {
            peer_ip,
            authority: canonicalize_authority(authority),
            alpn: canonicalize_alpn(alpn),
            transport: canonicalize_transport(transport),
        }
    }

    pub fn from_request(peer_ip: IpAddr, request: &UnifiedHttpRequest) -> Self {
        let authority = request
            .get_metadata("tls.sni")
            .map(String::as_str)
            .or_else(|| request.get_header("host").map(String::as_str));
        let alpn = request
            .get_metadata("tls.alpn")
            .map(String::as_str)
            .or_else(|| {
                Some(match request.version {
                    HttpVersion::Http2_0 => "h2",
                    HttpVersion::Http3_0 => "h3",
                    _ => "http/1.1",
                })
            });
        let transport = request
            .get_metadata("transport")
            .map(String::as_str)
            .unwrap_or_else(|| match request.version {
                HttpVersion::Http3_0 => "udp",
                _ if request.get_metadata("tls.sni").is_some() => "tls",
                _ => "http",
            });
        Self::from_parts(peer_ip, authority, alpn, transport)
    }

    fn coarse(&self) -> Self {
        Self {
            peer_ip: self.peer_ip,
            authority: self.authority.clone(),
            alpn: BucketAlpn::Unknown,
            transport: self.transport,
        }
    }

    fn peer_only(&self) -> Self {
        Self {
            peer_ip: self.peer_ip,
            authority: "*".to_string(),
            alpn: BucketAlpn::Unknown,
            transport: BucketTransport::Unknown,
        }
    }
}

impl BucketRuntime {
    fn new(now: Instant, unix_now: i64) -> Self {
        Self {
            last_seen_at: unix_now,
            last_seen_instant: now,
            state_since: unix_now,
            recent_connections: VecDeque::new(),
            recent_requests: VecDeque::new(),
            recent_feedback: VecDeque::new(),
            active_connections: 0,
            total_connections: 0,
            total_requests: 0,
            total_bytes: 0,
            l7_block_hits: 0,
            safeline_hits: 0,
            avg_connection_lifetime_ms: 0.0,
            score_ewma: 0.0,
            risk_level: L4BucketRiskLevel::Normal,
            cooldown_until: 0,
            protocol_hint: "unknown".to_string(),
        }
    }
}

async fn worker_loop(
    buckets: Arc<DashMap<BucketKey, BucketRuntime>>,
    mut receiver: mpsc::Receiver<BehaviorEvent>,
    max_buckets: usize,
    fallback_threshold: usize,
) {
    while let Some(event) = receiver.recv().await {
        let key = match &event {
            BehaviorEvent::ConnectionOpened { key, .. }
            | BehaviorEvent::ConnectionClosed { key, .. }
            | BehaviorEvent::RequestObserved { key, .. }
            | BehaviorEvent::Feedback { key, .. } => {
                canonicalize_storage_key(key, buckets.len(), max_buckets, fallback_threshold)
            }
        };

        {
            let mut bucket = buckets
                .entry(key.clone())
                .or_insert_with(|| BucketRuntime::new(Instant::now(), unix_timestamp()));
            match event {
                BehaviorEvent::ConnectionOpened {
                    connection_id,
                    now,
                    unix_now,
                    ..
                } => {
                    let _ = connection_id;
                    bucket.last_seen_at = unix_now;
                    bucket.last_seen_instant = now;
                    bucket.active_connections = bucket.active_connections.saturating_add(1);
                    bucket.total_connections = bucket.total_connections.saturating_add(1);
                    bucket.recent_connections.push_back(now);
                }
                BehaviorEvent::ConnectionClosed {
                    connection_id,
                    duration_ms,
                    now,
                    unix_now,
                    ..
                } => {
                    let _ = connection_id;
                    bucket.last_seen_at = unix_now;
                    bucket.last_seen_instant = now;
                    bucket.active_connections = bucket.active_connections.saturating_sub(1);
                    bucket.avg_connection_lifetime_ms = if bucket.avg_connection_lifetime_ms <= 0.0
                    {
                        duration_ms as f64
                    } else {
                        (bucket.avg_connection_lifetime_ms * 0.8) + (duration_ms as f64 * 0.2)
                    };
                }
                BehaviorEvent::RequestObserved {
                    bytes,
                    now,
                    unix_now,
                    ..
                } => {
                    bucket.last_seen_at = unix_now;
                    bucket.last_seen_instant = now;
                    bucket.total_requests = bucket.total_requests.saturating_add(1);
                    bucket.total_bytes = bucket.total_bytes.saturating_add(bytes);
                    bucket.recent_requests.push_back(now);
                }
                BehaviorEvent::Feedback {
                    source,
                    now,
                    unix_now,
                    ..
                } => {
                    bucket.last_seen_at = unix_now;
                    bucket.last_seen_instant = now;
                    bucket.recent_feedback.push_back(now);
                    match source {
                        FeedbackSource::L7Block => {
                            bucket.l7_block_hits = bucket.l7_block_hits.saturating_add(1)
                        }
                        FeedbackSource::SafeLine => {
                            bucket.safeline_hits = bucket.safeline_hits.saturating_add(1)
                        }
                    }
                }
            }

            let last_seen = bucket.last_seen_instant;
            prune_bucket(&mut bucket, last_seen);
            refresh_score_and_risk(&mut bucket, unix_timestamp());
        }

        if buckets.len() > max_buckets {
            evict_oldest(&buckets);
        }
    }
}

fn canonicalize_storage_key(
    key: &BucketKey,
    current_bucket_count: usize,
    max_buckets: usize,
    fallback_threshold: usize,
) -> BucketKey {
    if current_bucket_count < fallback_threshold {
        return key.clone();
    }
    if current_bucket_count < max_buckets {
        return key.coarse();
    }
    key.peer_only()
}

fn prune_bucket(bucket: &mut BucketRuntime, now: Instant) {
    prune_queue(&mut bucket.recent_connections, now, CONNECTION_WINDOW);
    prune_queue(&mut bucket.recent_requests, now, REQUEST_WINDOW);
    prune_queue(&mut bucket.recent_feedback, now, FEEDBACK_WINDOW);
}

fn prune_queue(queue: &mut VecDeque<Instant>, now: Instant, window: Duration) {
    while let Some(front) = queue.front() {
        if now.duration_since(*front) > window {
            queue.pop_front();
        } else {
            break;
        }
    }
}

fn extend_queue(target: &mut VecDeque<Instant>, source: &VecDeque<Instant>) {
    for item in source {
        target.push_back(*item);
    }
}

fn refresh_score_and_risk(bucket: &mut BucketRuntime, unix_now: i64) {
    let recent_connections = bucket.recent_connections.len() as f64;
    let recent_requests = bucket.recent_requests.len() as f64;
    let recent_feedback = bucket.recent_feedback.len() as f64;
    let requests_per_connection = if bucket.total_connections == 0 {
        0.0
    } else {
        bucket.total_requests as f64 / bucket.total_connections as f64
    };
    let active_connections = f64::from(bucket.active_connections);
    let short_lifetime_penalty =
        if bucket.avg_connection_lifetime_ms > 0.0 && bucket.avg_connection_lifetime_ms < 1500.0 {
            12.0
        } else {
            0.0
        };

    let raw_score = (recent_connections * 1.8)
        + recent_requests
        + (recent_feedback * 18.0)
        + (active_connections * 6.0)
        + if requests_per_connection < 1.2 && bucket.total_connections > 10 {
            12.0
        } else {
            0.0
        }
        + short_lifetime_penalty
        + if bucket.authority_unknown() { 6.0 } else { 0.0 }
        + if bucket.l7_block_hits + bucket.safeline_hits > 0 {
            (((bucket.l7_block_hits + bucket.safeline_hits) as f64
                / bucket.total_requests.max(1) as f64)
                * 100.0)
                .min(20.0)
        } else {
            0.0
        };

    let next_score = (bucket.score_ewma * 0.7) + (raw_score.min(100.0) * 0.3);
    bucket.score_ewma = next_score;

    let next_risk = match bucket.risk_level {
        L4BucketRiskLevel::Normal => {
            if next_score >= 70.0 {
                L4BucketRiskLevel::High
            } else if next_score >= 30.0 {
                L4BucketRiskLevel::Suspicious
            } else {
                L4BucketRiskLevel::Normal
            }
        }
        L4BucketRiskLevel::Suspicious => {
            if bucket.cooldown_until > unix_now {
                L4BucketRiskLevel::Suspicious
            } else if next_score >= 70.0 {
                L4BucketRiskLevel::High
            } else if next_score <= 18.0 {
                L4BucketRiskLevel::Normal
            } else {
                L4BucketRiskLevel::Suspicious
            }
        }
        L4BucketRiskLevel::High => {
            if bucket.cooldown_until > unix_now {
                L4BucketRiskLevel::High
            } else if next_score <= 50.0 {
                L4BucketRiskLevel::Suspicious
            } else {
                L4BucketRiskLevel::High
            }
        }
    };

    if next_risk != bucket.risk_level {
        bucket.risk_level = next_risk;
        bucket.state_since = unix_now;
        bucket.cooldown_until = unix_now + COOL_DOWN_SECS;
    }
}

fn policy_from_runtime(
    bucket: &BucketRuntime,
    overload_level: L4OverloadLevel,
    tuning: &L4BehaviorTuning,
) -> L4AdaptivePolicy {
    let mut budget = match bucket.risk_level {
        L4BucketRiskLevel::Normal => tuning.normal_connection_budget_per_minute,
        L4BucketRiskLevel::Suspicious => tuning.suspicious_connection_budget_per_minute,
        L4BucketRiskLevel::High => tuning.high_risk_connection_budget_per_minute,
    };
    let mut delay_ms = 0u64;
    match overload_level {
        L4OverloadLevel::High => {
            budget = scale_budget(budget, tuning.high_overload_budget_scale_percent);
            delay_ms = tuning.high_overload_delay_ms;
        }
        L4OverloadLevel::Critical => {
            budget = scale_budget(budget, tuning.critical_overload_budget_scale_percent);
            delay_ms = tuning.critical_overload_delay_ms;
        }
        L4OverloadLevel::Normal => {}
    }

    if exceeds_threshold(
        bucket.active_connections,
        budget,
        tuning.soft_delay_threshold_percent,
    ) {
        delay_ms = delay_ms.max(tuning.soft_delay_ms);
    }
    if exceeds_threshold(
        bucket.active_connections,
        budget,
        tuning.hard_delay_threshold_percent,
    ) {
        delay_ms = delay_ms.max(tuning.hard_delay_ms);
    }
    let reject_new_connections = exceeds_threshold(
        bucket.active_connections,
        budget,
        tuning.reject_threshold_percent,
    ) || (matches!(overload_level, L4OverloadLevel::Critical)
        && exceeds_threshold(
            bucket.active_connections,
            budget,
            tuning.critical_reject_threshold_percent,
        ));

    L4AdaptivePolicy {
        risk_level: bucket.risk_level.clone(),
        risk_score: bucket.score_ewma.round().clamp(0.0, 100.0) as u32,
        disable_keepalive: !matches!(bucket.risk_level, L4BucketRiskLevel::Normal),
        prefer_early_close: !matches!(bucket.risk_level, L4BucketRiskLevel::Normal),
        reject_new_connections,
        connection_budget_per_minute: budget.max(5),
        suggested_delay_ms: delay_ms,
    }
}

fn policy_snapshot(policy: &L4AdaptivePolicy) -> L4BucketPolicySnapshot {
    L4BucketPolicySnapshot {
        connection_budget_per_minute: policy.connection_budget_per_minute,
        shrink_idle_timeout: policy.prefer_early_close,
        disable_keepalive: policy.disable_keepalive,
        prefer_early_close: policy.prefer_early_close,
        reject_new_connections: policy.reject_new_connections,
        mode: match policy.risk_level {
            L4BucketRiskLevel::Normal => "pass".to_string(),
            L4BucketRiskLevel::Suspicious => "degrade".to_string(),
            L4BucketRiskLevel::High => "tighten".to_string(),
        },
        suggested_delay_ms: policy.suggested_delay_ms,
    }
}

fn default_policy(overload_level: L4OverloadLevel, tuning: &L4BehaviorTuning) -> L4AdaptivePolicy {
    let suggested_delay_ms = match overload_level {
        L4OverloadLevel::Critical => tuning.critical_overload_delay_ms.max(tuning.soft_delay_ms),
        L4OverloadLevel::High => (tuning.high_overload_delay_ms / 2).max(5),
        L4OverloadLevel::Normal => 0,
    };
    L4AdaptivePolicy {
        risk_level: L4BucketRiskLevel::Normal,
        risk_score: 0,
        disable_keepalive: false,
        prefer_early_close: false,
        reject_new_connections: false,
        connection_budget_per_minute: tuning.normal_connection_budget_per_minute,
        suggested_delay_ms,
    }
}

fn derive_overload_level(
    bucket_count: usize,
    max_buckets: usize,
    blocked_connections: u64,
    active_connections: u64,
    fallback_threshold: usize,
    dropped_events: u64,
    tuning: &L4BehaviorTuning,
) -> L4OverloadLevel {
    if bucket_count >= max_buckets || dropped_events >= tuning.event_drop_critical_threshold {
        return L4OverloadLevel::Critical;
    }
    if bucket_count >= fallback_threshold
        || blocked_connections >= tuning.overload_blocked_connections_threshold
        || active_connections >= tuning.overload_active_connections_threshold
    {
        return L4OverloadLevel::High;
    }
    L4OverloadLevel::Normal
}

fn scale_budget(base: u32, scale_percent: u8) -> u32 {
    ((u64::from(base) * u64::from(scale_percent)) / 100).max(1) as u32
}

fn exceeds_threshold(active_connections: u32, budget: u32, threshold_percent: u16) -> bool {
    let limit = (u64::from(budget.max(1)) * u64::from(threshold_percent)) / 100;
    u64::from(active_connections) > limit.max(1)
}

fn overload_reason(
    overload: L4OverloadLevel,
    blocked_connections: u64,
    active_connections: u64,
    bucket_count: usize,
    max_buckets: usize,
) -> Option<String> {
    match overload {
        L4OverloadLevel::Normal => None,
        L4OverloadLevel::High => Some(format!(
            "bucket_pressure={} blocked_connections={} active_connections={}",
            bucket_count, blocked_connections, active_connections
        )),
        L4OverloadLevel::Critical => Some(format!(
            "critical_pressure bucket_count={} max_buckets={}",
            bucket_count, max_buckets
        )),
    }
}

fn canonicalize_authority(authority: Option<&str>) -> String {
    let raw = authority
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("*");
    let host = raw
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or(raw)
        .trim();
    if host.is_empty() {
        return "*".to_string();
    }
    let without_port = if host.starts_with('[') {
        host.split(']')
            .next()
            .map(|value| format!("{value}]"))
            .unwrap_or_else(|| host.to_string())
    } else {
        host.split(':').next().unwrap_or(host).to_string()
    };
    without_port.to_ascii_lowercase()
}

fn canonicalize_alpn(alpn: Option<&str>) -> BucketAlpn {
    match alpn
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("unknown")
        .to_ascii_lowercase()
        .as_str()
    {
        "h2" => BucketAlpn::H2,
        "h3" => BucketAlpn::H3,
        "http/1.1" | "http1.1" | "http/1" => BucketAlpn::Http11,
        _ => BucketAlpn::Unknown,
    }
}

fn canonicalize_transport(transport: &str) -> BucketTransport {
    match transport.trim().to_ascii_lowercase().as_str() {
        "http" => BucketTransport::Http,
        "tls" | "https" => BucketTransport::Tls,
        "udp" | "quic" => BucketTransport::Udp,
        _ => BucketTransport::Unknown,
    }
}

fn risk_label(risk: &L4BucketRiskLevel) -> &'static str {
    match risk {
        L4BucketRiskLevel::Normal => "normal",
        L4BucketRiskLevel::Suspicious => "suspicious",
        L4BucketRiskLevel::High => "high",
    }
}

fn max_risk_level(current: &L4BucketRiskLevel, next: &L4BucketRiskLevel) -> L4BucketRiskLevel {
    match (current, next) {
        (L4BucketRiskLevel::High, _) | (_, L4BucketRiskLevel::High) => L4BucketRiskLevel::High,
        (L4BucketRiskLevel::Suspicious, _) | (_, L4BucketRiskLevel::Suspicious) => {
            L4BucketRiskLevel::Suspicious
        }
        _ => L4BucketRiskLevel::Normal,
    }
}

fn transport_label(transport: BucketTransport) -> &'static str {
    match transport {
        BucketTransport::Http => "http",
        BucketTransport::Tls => "tls",
        BucketTransport::Udp => "udp",
        BucketTransport::Unknown => "unknown",
    }
}

fn evict_oldest(buckets: &DashMap<BucketKey, BucketRuntime>) {
    if let Some(oldest_key) = buckets
        .iter()
        .min_by_key(|entry| entry.value().last_seen_at)
        .map(|entry| entry.key().clone())
    {
        buckets.remove(&oldest_key);
    }
}

fn unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

impl BucketRuntime {
    fn authority_unknown(&self) -> bool {
        self.protocol_hint == "unknown"
    }
}

impl Hash for L4OverloadLevel {
    fn hash<H: Hasher>(&self, state: &mut H) {
        std::mem::discriminant(self).hash(state);
    }
}

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
        );
        let _ = engine.observe_connection_open(
            "b".to_string(),
            &p2,
            Some("b.example"),
            None,
            "http",
            "http/1.1",
        );
        let _ = engine.observe_connection_open("c".to_string(), &p3, None, None, "tcp", "unknown");

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
            );
        }

        sleep(Duration::from_millis(50)).await;
        let snapshot = engine.snapshot(0, 0);
        assert!(snapshot.overview.dropped_events > 0);
        assert_ne!(snapshot.overview.overload_level, L4OverloadLevel::Critical);
    }
}
