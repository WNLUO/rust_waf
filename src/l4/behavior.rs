use crate::config::L4Config;
use crate::core::PacketInfo;
use crate::protocol::{HttpVersion, UnifiedHttpRequest};
use serde::Serialize;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const CONNECTION_WINDOW_SECS: u64 = 10;
const REQUEST_WINDOW_SECS: u64 = 10;
const FEEDBACK_WINDOW_SECS: u64 = 120;
const BUCKET_RETENTION_SECS: u64 = 600;

#[derive(Debug)]
pub struct L4BehaviorEngine {
    max_buckets: usize,
    max_tracked_ips: usize,
    max_blocked_ips: usize,
    inner: Mutex<HashMap<BucketKey, BucketRuntime>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct BucketKey {
    peer_ip: IpAddr,
    authority: String,
    alpn: String,
    transport: String,
}

#[derive(Debug, Clone)]
struct BucketRuntime {
    last_seen_at: i64,
    last_seen_instant: Instant,
    recent_connections: VecDeque<Instant>,
    recent_requests: VecDeque<Instant>,
    recent_feedback: VecDeque<Instant>,
    recent_connection_ids: HashSet<String>,
    total_connections: u64,
    total_requests: u64,
    total_bytes: u64,
    l7_block_hits: u64,
    safeline_hits: u64,
    protocol_hint: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum L4BucketRiskLevel {
    Normal,
    Suspicious,
    High,
}

#[derive(Debug, Clone, Serialize)]
pub struct L4BucketPolicySnapshot {
    pub connection_budget_per_minute: u32,
    pub shrink_idle_timeout: bool,
    pub disable_keepalive: bool,
    pub prefer_early_close: bool,
    pub mode: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct L4BucketSnapshot {
    pub peer_ip: String,
    pub authority: String,
    pub alpn: String,
    pub transport: String,
    pub protocol_hint: String,
    pub total_connections: u64,
    pub total_requests: u64,
    pub total_bytes: u64,
    pub recent_connections_10s: u64,
    pub recent_requests_10s: u64,
    pub recent_feedback_120s: u64,
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
    pub normal_buckets: u64,
    pub suspicious_buckets: u64,
    pub high_risk_buckets: u64,
    pub safeline_feedback_hits: u64,
    pub l7_feedback_hits: u64,
    pub overloaded: bool,
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
    pub connection_budget_per_minute: u32,
}

impl L4BehaviorEngine {
    pub fn new(config: &L4Config) -> Self {
        Self {
            max_buckets: config.max_tracked_ips.max(64),
            max_tracked_ips: config.max_tracked_ips.max(1),
            max_blocked_ips: config.max_blocked_ips.max(1),
            inner: Mutex::new(HashMap::new()),
        }
    }

    pub fn observe_connection(
        &self,
        packet: &PacketInfo,
        authority: Option<&str>,
        alpn: Option<&str>,
        transport: &str,
        protocol_hint: &str,
    ) {
        let now = Instant::now();
        let unix_now = unix_timestamp();
        let key = BucketKey::from_parts(packet.source_ip, authority, alpn, transport);
        let connection_id = packet_connection_id(packet);

        let mut buckets = self.inner.lock().expect("behavior buckets mutex poisoned");
        self.ensure_capacity(&mut buckets, &key);
        let bucket = buckets
            .entry(key)
            .or_insert_with(|| BucketRuntime::new(unix_now, now, protocol_hint));
        bucket.record_connection(unix_now, now, &connection_id, protocol_hint);
        prune_bucket(bucket, now);
    }

    pub fn observe_request(&self, packet: &PacketInfo, request: &UnifiedHttpRequest) {
        let now = Instant::now();
        let unix_now = unix_timestamp();
        let authority = bucket_authority(request);
        let alpn = bucket_alpn(request);
        let transport = request
            .get_metadata("transport")
            .cloned()
            .unwrap_or_else(|| infer_transport(request));
        let protocol_hint = request.version.to_string();

        let key = BucketKey::from_parts(packet.source_ip, Some(&authority), Some(&alpn), &transport);
        let connection_id = packet_connection_id(packet);
        let mut buckets = self.inner.lock().expect("behavior buckets mutex poisoned");
        self.ensure_capacity(&mut buckets, &key);
        let bucket = buckets
            .entry(key)
            .or_insert_with(|| BucketRuntime::new(unix_now, now, &protocol_hint));
        bucket.record_connection(unix_now, now, &connection_id, &protocol_hint);
        bucket.record_request(unix_now, now, request.to_inspection_string().len() as u64);
        prune_bucket(bucket, now);
    }

    pub fn observe_feedback(
        &self,
        packet: &PacketInfo,
        request: &UnifiedHttpRequest,
        source: FeedbackSource,
    ) {
        let now = Instant::now();
        let unix_now = unix_timestamp();
        let authority = bucket_authority(request);
        let alpn = bucket_alpn(request);
        let transport = request
            .get_metadata("transport")
            .cloned()
            .unwrap_or_else(|| infer_transport(request));
        let protocol_hint = request.version.to_string();
        let key = BucketKey::from_parts(packet.source_ip, Some(&authority), Some(&alpn), &transport);

        let mut buckets = self.inner.lock().expect("behavior buckets mutex poisoned");
        self.ensure_capacity(&mut buckets, &key);
        let bucket = buckets
            .entry(key)
            .or_insert_with(|| BucketRuntime::new(unix_now, now, &protocol_hint));
        bucket.record_feedback(unix_now, now, source);
        prune_bucket(bucket, now);
    }

    pub fn apply_policy(
        &self,
        packet: &PacketInfo,
        request: &mut UnifiedHttpRequest,
    ) -> L4AdaptivePolicy {
        self.observe_request(packet, request);

        let authority = bucket_authority(request);
        let alpn = bucket_alpn(request);
        let transport = request
            .get_metadata("transport")
            .cloned()
            .unwrap_or_else(|| infer_transport(request));
        let key = BucketKey::from_parts(packet.source_ip, Some(&authority), Some(&alpn), &transport);

        let buckets = self.inner.lock().expect("behavior buckets mutex poisoned");
        let Some(bucket) = buckets.get(&key) else {
            return default_policy();
        };
        let overloaded = self.is_overloaded_unlocked(&buckets);
        let policy = bucket_policy(&key, bucket, overloaded);

        request.add_metadata(
            "l4.bucket_risk".to_string(),
            risk_label(&policy.risk_level).to_string(),
        );
        request.add_metadata(
            "l4.bucket_score".to_string(),
            policy.risk_score.to_string(),
        );
        if policy.disable_keepalive {
            request.add_metadata("l4.force_close".to_string(), "true".to_string());
            request.add_metadata("proxy_connection_mode".to_string(), "close".to_string());
        }

        policy
    }

    pub fn snapshot(&self, blocked_connections: u64, active_connections: u64) -> L4BehaviorSnapshot {
        let now = Instant::now();
        let mut buckets = self.inner.lock().expect("behavior buckets mutex poisoned");
        buckets.retain(|_, bucket| now.duration_since(bucket.last_seen_instant).as_secs() <= BUCKET_RETENTION_SECS);
        for bucket in buckets.values_mut() {
            prune_bucket(bucket, now);
        }

        let overloaded = self.is_overloaded_unlocked(&buckets)
            || blocked_connections as usize >= (self.max_blocked_ips * 7) / 10
            || active_connections as usize >= (self.max_tracked_ips * 8) / 10;
        let overload_reason = if blocked_connections as usize >= (self.max_blocked_ips * 7) / 10 {
            Some("blocked_table_pressure".to_string())
        } else if active_connections as usize >= (self.max_tracked_ips * 8) / 10 {
            Some("tracked_peer_pressure".to_string())
        } else if overloaded {
            Some("bucket_pressure".to_string())
        } else {
            None
        };

        let mut normal_buckets = 0u64;
        let mut suspicious_buckets = 0u64;
        let mut high_risk_buckets = 0u64;
        let mut safeline_feedback_hits = 0u64;
        let mut l7_feedback_hits = 0u64;

        let mut top_buckets = buckets
            .iter()
            .map(|(key, bucket)| {
                safeline_feedback_hits += bucket.safeline_hits;
                l7_feedback_hits += bucket.l7_block_hits;
                let policy = bucket_policy(key, bucket, overloaded);
                match policy.risk_level {
                    L4BucketRiskLevel::Normal => normal_buckets += 1,
                    L4BucketRiskLevel::Suspicious => suspicious_buckets += 1,
                    L4BucketRiskLevel::High => high_risk_buckets += 1,
                }
                let risk_level = policy.risk_level.clone();
                L4BucketSnapshot {
                    peer_ip: key.peer_ip.to_string(),
                    authority: key.authority.clone(),
                    alpn: key.alpn.clone(),
                    transport: key.transport.clone(),
                    protocol_hint: bucket.protocol_hint.clone(),
                    total_connections: bucket.total_connections,
                    total_requests: bucket.total_requests,
                    total_bytes: bucket.total_bytes,
                    recent_connections_10s: bucket.recent_connections.len() as u64,
                    recent_requests_10s: bucket.recent_requests.len() as u64,
                    recent_feedback_120s: bucket.recent_feedback.len() as u64,
                    l7_block_hits: bucket.l7_block_hits,
                    safeline_hits: bucket.safeline_hits,
                    risk_score: policy.risk_score,
                    risk_level,
                    policy: bucket_policy_snapshot(&policy),
                    last_seen_at: bucket.last_seen_at,
                }
            })
            .collect::<Vec<_>>();

        top_buckets.sort_by(|left, right| {
            right
                .risk_score
                .cmp(&left.risk_score)
                .then(right.recent_feedback_120s.cmp(&left.recent_feedback_120s))
                .then(right.recent_connections_10s.cmp(&left.recent_connections_10s))
                .then(right.total_requests.cmp(&left.total_requests))
                .then(left.authority.cmp(&right.authority))
        });
        top_buckets.truncate(12);

        L4BehaviorSnapshot {
            overview: L4BehaviorOverview {
                bucket_count: buckets.len() as u64,
                normal_buckets,
                suspicious_buckets,
                high_risk_buckets,
                safeline_feedback_hits,
                l7_feedback_hits,
                overloaded,
                overload_reason,
            },
            top_buckets,
        }
    }

    fn ensure_capacity(&self, buckets: &mut HashMap<BucketKey, BucketRuntime>, key: &BucketKey) {
        if buckets.len() < self.max_buckets || buckets.contains_key(key) {
            return;
        }

        if let Some(oldest) = buckets
            .iter()
            .min_by_key(|(_, bucket)| bucket.last_seen_at)
            .map(|(key, _)| key.clone())
        {
            buckets.remove(&oldest);
        }
    }

    fn is_overloaded_unlocked(&self, buckets: &HashMap<BucketKey, BucketRuntime>) -> bool {
        buckets.iter().filter(|(key, bucket)| {
            let policy = bucket_policy(key, bucket, false);
            policy.risk_level == L4BucketRiskLevel::High
        }).count() >= 4
    }
}

#[derive(Debug, Clone, Copy)]
pub enum FeedbackSource {
    L7Block,
    SafeLine,
}

impl BucketKey {
    fn from_parts(
        peer_ip: IpAddr,
        authority: Option<&str>,
        alpn: Option<&str>,
        transport: &str,
    ) -> Self {
        Self {
            peer_ip,
            authority: normalize_field(authority, "unknown"),
            alpn: normalize_field(alpn, "unknown"),
            transport: normalize_field(Some(transport), "tcp"),
        }
    }
}

impl BucketRuntime {
    fn new(now_unix: i64, now: Instant, protocol_hint: &str) -> Self {
        Self {
            last_seen_at: now_unix,
            last_seen_instant: now,
            recent_connections: VecDeque::new(),
            recent_requests: VecDeque::new(),
            recent_feedback: VecDeque::new(),
            recent_connection_ids: HashSet::new(),
            total_connections: 0,
            total_requests: 0,
            total_bytes: 0,
            l7_block_hits: 0,
            safeline_hits: 0,
            protocol_hint: protocol_hint.to_string(),
        }
    }

    fn record_connection(
        &mut self,
        now_unix: i64,
        now: Instant,
        connection_id: &str,
        protocol_hint: &str,
    ) {
        self.last_seen_at = now_unix;
        self.last_seen_instant = now;
        if self.recent_connection_ids.insert(connection_id.to_string()) {
            self.total_connections += 1;
            self.recent_connections.push_back(now);
        }
        self.protocol_hint = protocol_hint.to_string();
    }

    fn record_request(&mut self, now_unix: i64, now: Instant, bytes: u64) {
        self.last_seen_at = now_unix;
        self.last_seen_instant = now;
        self.total_requests += 1;
        self.total_bytes = self.total_bytes.saturating_add(bytes);
        self.recent_requests.push_back(now);
    }

    fn record_feedback(&mut self, now_unix: i64, now: Instant, source: FeedbackSource) {
        self.last_seen_at = now_unix;
        self.last_seen_instant = now;
        self.recent_feedback.push_back(now);
        match source {
            FeedbackSource::L7Block => self.l7_block_hits += 1,
            FeedbackSource::SafeLine => self.safeline_hits += 1,
        }
    }
}

fn bucket_policy(key: &BucketKey, bucket: &BucketRuntime, overloaded: bool) -> L4AdaptivePolicy {
    let recent_connections = bucket.recent_connections.len() as u32;
    let recent_requests = bucket.recent_requests.len() as u32;
    let recent_feedback = bucket.recent_feedback.len() as u32;
    let block_ratio_score = if bucket.total_requests > 0 {
        (((bucket.l7_block_hits + bucket.safeline_hits) * 100) / bucket.total_requests).min(100) as u32
    } else {
        0
    };

    let mut risk_score = recent_connections.saturating_mul(2)
        + recent_requests
        + recent_feedback.saturating_mul(18)
        + block_ratio_score;
    if key.authority == "unknown" {
        risk_score = risk_score.saturating_add(6);
    }
    if recent_connections >= 20 {
        risk_score = risk_score.saturating_add(18);
    }
    if recent_feedback >= 2 {
        risk_score = risk_score.saturating_add(20);
    }
    if overloaded {
        risk_score = risk_score.saturating_add(12);
    }
    risk_score = risk_score.min(100);

    let risk_level = if risk_score >= 70 {
        L4BucketRiskLevel::High
    } else if risk_score >= 30 {
        L4BucketRiskLevel::Suspicious
    } else {
        L4BucketRiskLevel::Normal
    };

    match risk_level {
        L4BucketRiskLevel::Normal => L4AdaptivePolicy {
            risk_level,
            risk_score,
            disable_keepalive: false,
            prefer_early_close: false,
            connection_budget_per_minute: if overloaded { 90 } else { 120 },
        },
        L4BucketRiskLevel::Suspicious => L4AdaptivePolicy {
            risk_level,
            risk_score,
            disable_keepalive: true,
            prefer_early_close: true,
            connection_budget_per_minute: 60,
        },
        L4BucketRiskLevel::High => L4AdaptivePolicy {
            risk_level,
            risk_score,
            disable_keepalive: true,
            prefer_early_close: true,
            connection_budget_per_minute: 20,
        },
    }
}

fn bucket_policy_snapshot(policy: &L4AdaptivePolicy) -> L4BucketPolicySnapshot {
    L4BucketPolicySnapshot {
        connection_budget_per_minute: policy.connection_budget_per_minute,
        shrink_idle_timeout: policy.prefer_early_close,
        disable_keepalive: policy.disable_keepalive,
        prefer_early_close: policy.prefer_early_close,
        mode: match policy.risk_level {
            L4BucketRiskLevel::Normal => "pass".to_string(),
            L4BucketRiskLevel::Suspicious => "degrade".to_string(),
            L4BucketRiskLevel::High => "tighten".to_string(),
        },
    }
}

fn prune_bucket(bucket: &mut BucketRuntime, now: Instant) {
    prune_queue(&mut bucket.recent_connections, now, Duration::from_secs(CONNECTION_WINDOW_SECS));
    prune_queue(&mut bucket.recent_requests, now, Duration::from_secs(REQUEST_WINDOW_SECS));
    prune_queue(&mut bucket.recent_feedback, now, Duration::from_secs(FEEDBACK_WINDOW_SECS));
    if bucket.recent_connections.is_empty() {
        bucket.recent_connection_ids.clear();
    }
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

fn bucket_authority(request: &UnifiedHttpRequest) -> String {
    request
        .get_metadata("tls.sni")
        .cloned()
        .or_else(|| request.get_header("host").cloned())
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

fn bucket_alpn(request: &UnifiedHttpRequest) -> String {
    request
        .get_metadata("tls.alpn")
        .cloned()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| match request.version {
            HttpVersion::Http1_0 | HttpVersion::Http1_1 => "http/1.1".to_string(),
            HttpVersion::Http2_0 => "h2".to_string(),
            HttpVersion::Http3_0 => "h3".to_string(),
        })
}

fn infer_transport(request: &UnifiedHttpRequest) -> String {
    match request.version {
        HttpVersion::Http3_0 => "udp".to_string(),
        _ => {
            if request.get_metadata("tls.sni").is_some() || request.get_metadata("tls.alpn").is_some() {
                "tls".to_string()
            } else {
                "http".to_string()
            }
        }
    }
}

fn normalize_field(value: Option<&str>, fallback: &str) -> String {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(fallback)
        .to_ascii_lowercase()
}

fn packet_connection_id(packet: &PacketInfo) -> String {
    format!(
        "{}:{}-{}:{}-{}",
        packet.source_ip, packet.source_port, packet.dest_ip, packet.dest_port, packet.timestamp
    )
}

fn unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn risk_label(risk: &L4BucketRiskLevel) -> &'static str {
    match risk {
        L4BucketRiskLevel::Normal => "normal",
        L4BucketRiskLevel::Suspicious => "suspicious",
        L4BucketRiskLevel::High => "high",
    }
}

fn default_policy() -> L4AdaptivePolicy {
    L4AdaptivePolicy {
        risk_level: L4BucketRiskLevel::Normal,
        risk_score: 0,
        disable_keepalive: false,
        prefer_early_close: false,
        connection_budget_per_minute: 120,
    }
}
