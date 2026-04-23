use super::policy::{
    apply_identity_state_policy, canonicalize_transport, default_policy, derive_overload_level,
    max_risk_level, merge_policies, overload_reason, policy_from_runtime, policy_snapshot,
    resolve_request_bucket_ip, risk_label, transport_label,
};
use super::runtime::{extend_queue, unix_timestamp, worker_loop};
use super::*;
use crate::locks::{mutex_lock, read_lock, write_lock};
use std::sync::RwLock;

impl L4BehaviorTuning {
    pub(super) fn from_config(config: &L4Config) -> Self {
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
        let tuning = Arc::new(RwLock::new(L4BehaviorTuning::from_config(config)));
        let (sender, receiver) = mpsc::channel(config.behavior_event_channel_capacity);
        let dropped_events = Arc::new(AtomicU64::new(0));
        let max_buckets = config.max_tracked_ips.max(128);
        let fallback_threshold =
            max_buckets.saturating_mul(config.behavior_fallback_ratio_percent as usize) / 100;

        Self {
            buckets,
            sender,
            worker_receiver: Mutex::new(Some(receiver)),
            dropped_events,
            max_buckets,
            fallback_threshold,
            tuning,
        }
    }

    pub fn update_tuning(&self, config: &L4Config) {
        let mut guard = write_lock(&self.tuning, "behavior tuning");
        *guard = L4BehaviorTuning::from_config(config);
    }

    pub fn start(&self) {
        let receiver = {
            let mut guard = mutex_lock(&self.worker_receiver, "behavior worker receiver");
            guard.take()
        };

        if let Some(receiver) = receiver {
            tokio::spawn(worker_loop(
                Arc::clone(&self.buckets),
                receiver,
                self.max_buckets,
                self.fallback_threshold,
            ));
        }
    }

    pub fn pre_admission_policy(&self, peer_ip: IpAddr, transport: &str) -> L4AdaptivePolicy {
        self.pre_admission_policy_for_peer(peer_ip, transport, BucketPeerKind::DirectClient)
    }

    pub fn pre_admission_policy_for_peer(
        &self,
        peer_ip: IpAddr,
        transport: &str,
        peer_kind: BucketPeerKind,
    ) -> L4AdaptivePolicy {
        let overload_level = self.current_overload_level();
        let tuning = read_lock(&self.tuning, "behavior tuning").clone();
        self.aggregate_for_peer_transport(peer_ip, canonicalize_transport(transport), peer_kind)
            .map(|bucket| policy_from_runtime(&bucket, overload_level.clone(), &tuning))
            .unwrap_or_else(|| default_policy(overload_level, &tuning))
    }

    pub fn observe_connection_open(
        &self,
        connection_id: String,
        packet: &PacketInfo,
        authority: Option<&str>,
        alpn: Option<&str>,
        transport: &str,
        protocol_hint: &str,
        peer_kind: BucketPeerKind,
    ) -> BucketKey {
        let key = BucketKey::from_parts(packet.source_ip, peer_kind, authority, alpn, transport);
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
        let client_bucket_ip = resolve_request_bucket_ip(packet, request);
        let key = BucketKey::from_request(client_bucket_ip, request);
        let peer_key = trusted_forwarded_peer_bucket_key(packet, request, &key);
        let overload_level = self.current_overload_level();
        let tuning = self
            .tuning
            .read()
            .map(|guard| guard.clone())
            .unwrap_or_else(|poisoned| {
                log::warn!("behavior tuning lock poisoned; recovering with current value");
                poisoned.into_inner().clone()
            });
        let mut policy = self
            .policy_for_key(&key, overload_level.clone())
            .unwrap_or_else(|| default_policy(overload_level.clone(), &tuning));
        request.add_metadata(
            "l4.client_bucket_risk".to_string(),
            risk_label(&policy.risk_level).to_string(),
        );
        request.add_metadata(
            "l4.client_bucket_score".to_string(),
            policy.risk_score.to_string(),
        );
        if let Some(peer_key) = peer_key.as_ref() {
            let peer_policy = self
                .policy_for_key(peer_key, overload_level.clone())
                .unwrap_or_else(|| default_policy(overload_level.clone(), &tuning));
            request.add_metadata(
                "l4.peer_bucket_risk".to_string(),
                risk_label(&peer_policy.risk_level).to_string(),
            );
            request.add_metadata(
                "l4.peer_bucket_score".to_string(),
                peer_policy.risk_score.to_string(),
            );
            policy = merge_policies(policy, peer_policy);
            request.add_metadata("l4.dual_identity_budget".to_string(), "true".to_string());
            request.add_metadata(
                "l4.peer_bucket_ip".to_string(),
                peer_key.peer_ip.to_string(),
            );
            request.add_metadata(
                "l4.client_bucket_ip".to_string(),
                client_bucket_ip.to_string(),
            );
        }
        let policy = apply_identity_state_policy(policy, request, &overload_level, &tuning);

        let bytes = request.to_inspection_string().len() as u64;
        self.try_send(BehaviorEvent::RequestObserved {
            key: key.clone(),
            bytes,
            now: Instant::now(),
            unix_now: unix_timestamp(),
        });
        if let Some(peer_key) = peer_key {
            self.try_send(BehaviorEvent::RequestObserved {
                key: peer_key,
                bytes,
                now: Instant::now(),
                unix_now: unix_timestamp(),
            });
        }

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
        if let Some(identity_state) = request.get_metadata("network.identity_state").cloned() {
            request.add_metadata("l4.identity_state".to_string(), identity_state);
        }
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
        if let Some(value) = policy.l7_route_threshold_scale_percent {
            set_min_percent_metadata(request, "ai.cc.route_threshold_scale_percent", value);
            request.add_metadata(
                "l4.l7_route_threshold_scale_percent".to_string(),
                value.to_string(),
            );
        }
        if let Some(value) = policy.l7_host_threshold_scale_percent {
            set_min_percent_metadata(request, "ai.cc.host_threshold_scale_percent", value);
            request.add_metadata(
                "l4.l7_host_threshold_scale_percent".to_string(),
                value.to_string(),
            );
        }
        if policy.route_survival_hint {
            request.add_metadata("l4.route_survival_hint".to_string(), "true".to_string());
            request.add_metadata("runtime.defense.depth".to_string(), "survival".to_string());
            request.add_metadata(
                "runtime.route.defense_depth".to_string(),
                "survival".to_string(),
            );
            request.add_metadata(
                "runtime.site.defense_reason".to_string(),
                "l4_dual_identity_pressure".to_string(),
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
        let key = BucketKey::from_request(resolve_request_bucket_ip(packet, request), request);
        self.try_send(BehaviorEvent::Feedback {
            key: key.clone(),
            source,
            now: Instant::now(),
            unix_now: unix_timestamp(),
        });
        if let Some(peer_key) = trusted_forwarded_peer_bucket_key(packet, request, &key) {
            self.try_send(BehaviorEvent::Feedback {
                key: peer_key,
                source,
                now: Instant::now(),
                unix_now: unix_timestamp(),
            });
        }
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
            &read_lock(&self.tuning, "behavior tuning").clone(),
        );
        let tuning = read_lock(&self.tuning, "behavior tuning").clone();

        let mut normal_buckets = 0u64;
        let mut fine_grained_buckets = 0u64;
        let mut coarse_buckets = 0u64;
        let mut peer_only_buckets = 0u64;
        let mut direct_idle_no_request_buckets = 0u64;
        let mut direct_idle_no_request_connections = 0u64;
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
                if entry.key().peer_kind == BucketPeerKind::DirectClient
                    && bucket.total_requests == 0
                    && bucket.active_connections > 0
                {
                    direct_idle_no_request_buckets += 1;
                    direct_idle_no_request_connections += u64::from(bucket.active_connections);
                }
                let policy = policy_from_runtime(bucket, overload_level.clone(), &tuning);
                L4BucketSnapshot {
                    peer_ip: entry.key().peer_ip.to_string(),
                    peer_kind: entry.key().peer_kind,
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
                    slow_attack_hits: bucket.slow_attack_hits,
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
                direct_idle_no_request_buckets,
                direct_idle_no_request_connections,
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
        let tuning = read_lock(&self.tuning, "behavior tuning").clone();
        self.policy_for_key(key, overload_level.clone())
            .unwrap_or_else(|| default_policy(overload_level, &tuning))
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
        let tuning = read_lock(&self.tuning, "behavior tuning").clone();
        self.lookup_bucket(key)
            .map(|bucket| policy_from_runtime(&bucket, overload_level, &tuning))
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
            &read_lock(&self.tuning, "behavior tuning").clone(),
        )
    }

    fn aggregate_for_peer_transport(
        &self,
        peer_ip: IpAddr,
        transport: BucketTransport,
        peer_kind: BucketPeerKind,
    ) -> Option<BucketRuntime> {
        let mut aggregate: Option<BucketRuntime> = None;
        for entry in self.buckets.iter() {
            if entry.key().peer_ip != peer_ip {
                continue;
            }
            if entry.key().peer_kind != peer_kind {
                continue;
            }
            if transport != BucketTransport::Unknown && entry.key().transport != transport {
                continue;
            }
            let bucket = entry.value();
            let next = aggregate.get_or_insert_with(|| {
                BucketRuntime::new(
                    bucket.peer_kind,
                    bucket.last_seen_instant,
                    bucket.last_seen_at,
                )
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

fn trusted_forwarded_peer_bucket_key(
    packet: &PacketInfo,
    request: &UnifiedHttpRequest,
    client_key: &BucketKey,
) -> Option<BucketKey> {
    if !matches!(
        request
            .get_metadata("network.identity_state")
            .map(String::as_str),
        Some("trusted_cdn_forwarded")
    ) {
        return None;
    }

    if client_key.peer_ip == packet.source_ip {
        return None;
    }

    let peer_key = BucketKey::from_request(packet.source_ip, request);
    (peer_key != *client_key).then_some(peer_key)
}

fn set_min_percent_metadata(request: &mut UnifiedHttpRequest, key: &str, value: u32) {
    let next = request
        .get_metadata(key)
        .and_then(|current| current.parse::<u32>().ok())
        .map(|current| current.min(value))
        .unwrap_or(value)
        .clamp(10, 100);
    request.add_metadata(key.to_string(), next.to_string());
}
