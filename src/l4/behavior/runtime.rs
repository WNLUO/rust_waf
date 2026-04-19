use super::policy::{
    canonicalize_alpn, canonicalize_authority, canonicalize_transport, refresh_score_and_risk,
};
use super::*;
use std::time::{SystemTime, UNIX_EPOCH};

impl BucketKey {
    pub fn from_parts(
        peer_ip: IpAddr,
        peer_kind: BucketPeerKind,
        authority: Option<&str>,
        alpn: Option<&str>,
        transport: &str,
    ) -> Self {
        Self {
            peer_ip,
            peer_kind,
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
        let alpn = request.get_metadata("tls.alpn").map(String::as_str).or({
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
        Self::from_parts(
            peer_ip,
            request_bucket_peer_kind(peer_ip, request),
            authority,
            alpn,
            transport,
        )
    }

    pub(super) fn coarse(&self) -> Self {
        Self {
            peer_ip: self.peer_ip,
            peer_kind: self.peer_kind,
            authority: self.authority.clone(),
            alpn: BucketAlpn::Unknown,
            transport: self.transport,
        }
    }

    pub(super) fn peer_only(&self) -> Self {
        Self {
            peer_ip: self.peer_ip,
            peer_kind: self.peer_kind,
            authority: "*".to_string(),
            alpn: BucketAlpn::Unknown,
            transport: BucketTransport::Unknown,
        }
    }
}

impl BucketRuntime {
    pub(super) fn new(peer_kind: BucketPeerKind, now: Instant, unix_now: i64) -> Self {
        Self {
            peer_kind,
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
            slow_attack_hits: 0,
            avg_connection_lifetime_ms: 0.0,
            score_ewma: 0.0,
            risk_level: L4BucketRiskLevel::Normal,
            cooldown_until: 0,
            protocol_hint: "unknown".to_string(),
        }
    }

    pub(super) fn authority_unknown(&self) -> bool {
        self.protocol_hint == "unknown"
    }
}

pub(super) async fn worker_loop(
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
            let mut bucket = buckets.entry(key.clone()).or_insert_with(|| {
                BucketRuntime::new(key.peer_kind, Instant::now(), unix_timestamp())
            });
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
                        FeedbackSource::SlowAttack => {
                            bucket.slow_attack_hits = bucket.slow_attack_hits.saturating_add(1)
                        }
                    }
                }
            }

            let last_seen = bucket.last_seen_instant;
            prune_bucket(&mut bucket, last_seen);
            refresh_score_and_risk(&mut bucket, unix_timestamp());
        }

        if buckets.len() > max_buckets {
            evict_worst(&buckets);
        }
    }
}

pub(super) fn canonicalize_storage_key(
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

pub(super) fn extend_queue(target: &mut VecDeque<Instant>, source: &VecDeque<Instant>) {
    for item in source {
        target.push_back(*item);
    }
}

fn evict_worst(buckets: &DashMap<BucketKey, BucketRuntime>) {
    let now = unix_timestamp();
    if let Some(worst_key) = buckets
        .iter()
        .max_by_key(|entry| eviction_priority(entry.key(), entry.value(), now))
        .map(|entry| entry.key().clone())
    {
        buckets.remove(&worst_key);
    }
}

fn eviction_priority(key: &BucketKey, bucket: &BucketRuntime, now: i64) -> (u8, u8, u64, u64, u64) {
    let direct_priority = match key.peer_kind {
        BucketPeerKind::DirectClient => 1,
        BucketPeerKind::TrustedProxy => 0,
    };
    let no_request_priority = if bucket.total_requests == 0 { 1 } else { 0 };
    let risk_score = match bucket.risk_level {
        L4BucketRiskLevel::High => 100,
        L4BucketRiskLevel::Suspicious => 60,
        L4BucketRiskLevel::Normal => bucket.score_ewma.round().clamp(0.0, 50.0) as u64,
    };
    let unknown_priority =
        u64::from(key.alpn == BucketAlpn::Unknown || key.transport == BucketTransport::Unknown)
            + u64::from(bucket.authority_unknown());
    let feedback_score = bucket
        .l7_block_hits
        .saturating_add(bucket.safeline_hits)
        .saturating_add(bucket.slow_attack_hits)
        .min(100);
    let active_no_request_score = if bucket.total_requests == 0 {
        u64::from(bucket.active_connections).saturating_mul(8)
    } else {
        0
    };
    let stale_score = now.saturating_sub(bucket.last_seen_at).max(0) as u64;
    let resource_score = risk_score
        .saturating_add(unknown_priority.saturating_mul(10))
        .saturating_add(feedback_score.saturating_mul(4))
        .saturating_add(active_no_request_score)
        .saturating_add(stale_score.min(3_600));

    (
        direct_priority,
        no_request_priority,
        resource_score,
        u64::from(bucket.active_connections),
        stale_score,
    )
}

pub(super) fn unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn request_bucket_peer_kind(peer_ip: IpAddr, request: &UnifiedHttpRequest) -> BucketPeerKind {
    match request
        .get_metadata("network.identity_state")
        .map(String::as_str)
    {
        Some("trusted_cdn_forwarded") => return BucketPeerKind::TrustedProxy,
        Some("trusted_cdn_unresolved" | "spoofed_forward_header" | "direct_client") => {
            return BucketPeerKind::DirectClient;
        }
        _ => {}
    }

    match request
        .get_metadata("network.client_ip_source")
        .map(String::as_str)
    {
        Some("forwarded_header") | Some("proxy_protocol") => {
            return BucketPeerKind::DirectClient;
        }
        _ => {}
    }

    let peer_matches_socket = request
        .get_metadata("network.peer_ip")
        .and_then(|value| value.parse::<IpAddr>().ok())
        .map(|socket_peer| socket_peer == peer_ip)
        .unwrap_or(false);
    if !peer_matches_socket {
        return BucketPeerKind::DirectClient;
    }

    if forwarded_header_ip(request).is_some_and(|forwarded_ip| forwarded_ip != peer_ip) {
        return BucketPeerKind::TrustedProxy;
    }

    BucketPeerKind::DirectClient
}

fn forwarded_header_ip(request: &UnifiedHttpRequest) -> Option<IpAddr> {
    request
        .get_header("cf-connecting-ip")
        .and_then(|value| value.parse::<IpAddr>().ok())
        .or_else(|| {
            request
                .get_header("true-client-ip")
                .and_then(|value| value.parse::<IpAddr>().ok())
        })
        .or_else(|| {
            request
                .get_header("x-forwarded-for")
                .and_then(|value| value.split(',').next())
                .and_then(|value| value.trim().parse::<IpAddr>().ok())
        })
        .or_else(|| {
            request
                .get_header("x-real-ip")
                .and_then(|value| value.parse::<IpAddr>().ok())
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn key(ip: u8, authority: Option<&str>, alpn: Option<&str>) -> BucketKey {
        BucketKey::from_parts(
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, ip)),
            BucketPeerKind::DirectClient,
            authority,
            alpn,
            "tls",
        )
    }

    #[test]
    fn evict_worst_prefers_direct_idle_no_request_bucket_over_normal_traffic() {
        let buckets = DashMap::new();
        let now = unix_timestamp();
        let good_key = key(1, Some("www.example"), Some("h2"));
        let bad_key = key(2, None, None);
        let mut good = BucketRuntime::new(BucketPeerKind::DirectClient, Instant::now(), now);
        good.total_connections = 24;
        good.total_requests = 80;
        good.active_connections = 1;
        good.score_ewma = 8.0;

        let mut bad = BucketRuntime::new(BucketPeerKind::DirectClient, Instant::now(), now);
        bad.total_connections = 40;
        bad.total_requests = 0;
        bad.active_connections = 12;
        bad.score_ewma = 90.0;
        bad.risk_level = L4BucketRiskLevel::High;
        bad.protocol_hint = "unknown".to_string();

        buckets.insert(good_key.clone(), good);
        buckets.insert(bad_key.clone(), bad);

        evict_worst(&buckets);

        assert!(buckets.contains_key(&good_key));
        assert!(!buckets.contains_key(&bad_key));
    }

    #[test]
    fn evict_worst_preserves_trusted_proxy_when_direct_bucket_is_comparable() {
        let buckets = DashMap::new();
        let now = unix_timestamp();
        let proxy_key = BucketKey::from_parts(
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 3)),
            BucketPeerKind::TrustedProxy,
            Some("cdn.example"),
            Some("h2"),
            "tls",
        );
        let direct_key = key(4, None, None);
        let mut proxy = BucketRuntime::new(BucketPeerKind::TrustedProxy, Instant::now(), now);
        proxy.total_connections = 200;
        proxy.total_requests = 40;
        proxy.active_connections = 20;
        proxy.score_ewma = 75.0;
        proxy.risk_level = L4BucketRiskLevel::Suspicious;

        let mut direct = BucketRuntime::new(BucketPeerKind::DirectClient, Instant::now(), now);
        direct.total_connections = 4;
        direct.total_requests = 0;
        direct.active_connections = 4;
        direct.score_ewma = 60.0;
        direct.risk_level = L4BucketRiskLevel::Suspicious;
        direct.protocol_hint = "unknown".to_string();

        buckets.insert(proxy_key.clone(), proxy);
        buckets.insert(direct_key.clone(), direct);

        evict_worst(&buckets);

        assert!(buckets.contains_key(&proxy_key));
        assert!(!buckets.contains_key(&direct_key));
    }
}
