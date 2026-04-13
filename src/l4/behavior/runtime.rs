use super::policy::{
    canonicalize_alpn, canonicalize_authority, canonicalize_transport, refresh_score_and_risk,
};
use super::*;
use std::time::{SystemTime, UNIX_EPOCH};

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
        Self::from_parts(peer_ip, authority, alpn, transport)
    }

    pub(super) fn coarse(&self) -> Self {
        Self {
            peer_ip: self.peer_ip,
            authority: self.authority.clone(),
            alpn: BucketAlpn::Unknown,
            transport: self.transport,
        }
    }

    pub(super) fn peer_only(&self) -> Self {
        Self {
            peer_ip: self.peer_ip,
            authority: "*".to_string(),
            alpn: BucketAlpn::Unknown,
            transport: BucketTransport::Unknown,
        }
    }
}

impl BucketRuntime {
    pub(super) fn new(now: Instant, unix_now: i64) -> Self {
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

fn evict_oldest(buckets: &DashMap<BucketKey, BucketRuntime>) {
    if let Some(oldest_key) = buckets
        .iter()
        .min_by_key(|entry| entry.value().last_seen_at)
        .map(|entry| entry.key().clone())
    {
        buckets.remove(&oldest_key);
    }
}

pub(super) fn unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
