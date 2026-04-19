use super::{RuntimePressureSnapshot, WafContext};
use crate::storage::{SecurityEventRecord, SqliteStore};
use dashmap::DashMap;
use serde::Serialize;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicI64, AtomicU64, AtomicU8, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const MODE_NORMAL: u8 = 0;
const MODE_ELEVATED: u8 = 1;
const MODE_UNDER_ATTACK: u8 = 2;
const MODE_SURVIVAL: u8 = 3;

const SCORE_ELEVATED: u64 = 30;
const SCORE_UNDER_ATTACK: u64 = 80;
const SCORE_SURVIVAL: u64 = 180;
const SCORE_CAP: u64 = 500;

const DEBT_HIGH: i64 = 70;
const DEBT_EXTREME: i64 = 120;
const DEBT_CAP: i64 = 240;
const NEW_CLUSTER_BUDGET_WINDOW_MS: u64 = 100;
const UNDER_ATTACK_NEW_CLUSTER_BUDGET: u64 = 64;
const SURVIVAL_NEW_CLUSTER_BUDGET: u64 = 16;
const IP_COOLDOWN_MS: u64 = 30_000;
const CLUSTER_COOLDOWN_MS: u64 = 10_000;
const HOT_EVENT_CLUSTER_COUNT: u64 = 32;
const HOT_EVENT_CLUSTER_SCORE: u64 = 120;
const HOT_EVENT_SAMPLE_INTERVAL: u64 = 16;

#[derive(Debug)]
pub(crate) struct ResourceSentinel {
    mode: AtomicU8,
    attack_score: AtomicU64,
    last_decay_ms: AtomicU64,
    last_escalation_ms: AtomicU64,
    connection_debt: DashMap<String, DebtBucket>,
    cooldowns: DashMap<String, CooldownBucket>,
    attack_clusters: DashMap<String, AttackClusterBucket>,
    new_cluster_budget_window_ms: AtomicU64,
    new_cluster_budget_used: AtomicU64,
    pre_admission_rejections: AtomicU64,
    aggregated_events: AtomicU64,
}

#[derive(Debug)]
struct DebtBucket {
    score: AtomicI64,
    last_seen_ms: AtomicU64,
}

#[derive(Debug)]
struct CooldownBucket {
    until_ms: AtomicU64,
    reason: String,
}

#[derive(Debug)]
struct AttackClusterBucket {
    cluster: String,
    attack_type: String,
    transport: String,
    reason: String,
    sample_ip: String,
    count: AtomicU64,
    admitted: AtomicU64,
    rejected: AtomicU64,
    aggregated: AtomicU64,
    score: AtomicU64,
    first_seen_ms: u64,
    last_seen_ms: AtomicU64,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct ResourceSentinelSnapshot {
    pub mode: String,
    pub attack_score: u64,
    pub tracked_debt_buckets: u64,
    pub high_debt_buckets: u64,
    pub extreme_debt_buckets: u64,
    pub tracked_attack_clusters: u64,
    pub active_cooldowns: u64,
    pub pre_admission_rejections: u64,
    pub aggregated_events: u64,
    pub top_attack_clusters: Vec<ResourceSentinelClusterSnapshot>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct ResourceSentinelClusterSnapshot {
    pub cluster: String,
    pub attack_type: String,
    pub transport: String,
    pub reason: String,
    pub sample_ip: String,
    pub count: u64,
    pub admitted: u64,
    pub rejected: u64,
    pub aggregated: u64,
    pub score: u64,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct AdmissionDecision {
    pub allow: bool,
    pub reason: Option<String>,
}

impl ResourceSentinel {
    pub(crate) fn new() -> Self {
        let now = now_millis();
        Self {
            mode: AtomicU8::new(MODE_NORMAL),
            attack_score: AtomicU64::new(0),
            last_decay_ms: AtomicU64::new(now),
            last_escalation_ms: AtomicU64::new(now),
            connection_debt: DashMap::new(),
            cooldowns: DashMap::new(),
            attack_clusters: DashMap::new(),
            new_cluster_budget_window_ms: AtomicU64::new(window_start(now)),
            new_cluster_budget_used: AtomicU64::new(0),
            pre_admission_rejections: AtomicU64::new(0),
            aggregated_events: AtomicU64::new(0),
        }
    }

    pub(crate) fn admit_connection(
        &self,
        peer_ip: IpAddr,
        transport: &str,
        available_connection_permits: usize,
        storage_queue_usage_percent: u64,
    ) -> AdmissionDecision {
        self.decay_if_needed();

        let mode = self.mode.load(Ordering::Relaxed);
        let debt = self.debt_score(peer_ip);
        if let Some(reason) = self.active_cooldown_reason(peer_ip) {
            self.pre_admission_rejections
                .fetch_add(1, Ordering::Relaxed);
            self.record_cluster_rejected(peer_ip, "cooldown_reject", transport, &reason, 18);
            self.note_signal(18);
            return AdmissionDecision {
                allow: false,
                reason: Some(format!(
                    "resource sentinel rejected {transport} connection: mode={} cooldown={} debt={} available_connection_permits={} storage_queue={}%",
                    mode_label(mode),
                    reason,
                    debt,
                    available_connection_permits,
                    storage_queue_usage_percent
                )),
            };
        }
        let permits_low = available_connection_permits <= 4;
        let storage_hot = storage_queue_usage_percent >= 90;
        let high_debt_reject = match mode {
            MODE_SURVIVAL => debt >= DEBT_HIGH || (permits_low && debt >= 25) || storage_hot,
            MODE_UNDER_ATTACK => debt >= DEBT_EXTREME || (permits_low && debt >= 45),
            MODE_ELEVATED => permits_low && debt >= DEBT_EXTREME,
            _ => false,
        };
        let budget_reject = !high_debt_reject
            && mode >= MODE_UNDER_ATTACK
            && self.is_new_cluster(peer_ip)
            && !self.consume_new_cluster_budget(mode);

        if high_debt_reject || budget_reject {
            self.pre_admission_rejections
                .fetch_add(1, Ordering::Relaxed);
            let reason = if budget_reject {
                "new_cluster_budget"
            } else {
                "resource_debt"
            };
            self.record_cluster_rejected(peer_ip, "pre_admission_reject", transport, reason, 18);
            self.note_signal(18);
            return AdmissionDecision {
                allow: false,
                reason: Some(format!(
                    "resource sentinel rejected {transport} connection: mode={} reason={} debt={} available_connection_permits={} storage_queue={}%",
                    mode_label(mode),
                    reason,
                    debt,
                    available_connection_permits,
                    storage_queue_usage_percent
                )),
            };
        }

        if mode >= MODE_UNDER_ATTACK {
            self.add_debt(peer_ip, 0);
            self.record_cluster_admitted(peer_ip, "admitted", transport, "resource_budget", 0);
        }
        AdmissionDecision {
            allow: true,
            reason: None,
        }
    }

    pub(crate) fn note_tls_timeout(&self, peer_ip: IpAddr) {
        self.add_debt(peer_ip, 12);
        self.record_cluster_observed(peer_ip, "slow_tls_handshake", "tls", "timeout", 10);
        self.note_signal(10);
        self.cooldown_if_extreme(peer_ip, "slow_tls_handshake");
    }

    pub(crate) fn note_tls_failure(&self, peer_ip: IpAddr) {
        self.add_debt(peer_ip, 6);
        self.record_cluster_observed(
            peer_ip,
            "tls_handshake_failure",
            "tls",
            "handshake_error",
            4,
        );
        self.note_signal(4);
        self.cooldown_if_extreme(peer_ip, "tls_handshake_failure");
    }

    pub(crate) fn note_no_request_timeout(&self, peer_ip: IpAddr) {
        self.add_debt(peer_ip, 10);
        self.record_cluster_observed(peer_ip, "idle_no_request", "http", "no_request_timeout", 8);
        self.note_signal(8);
        self.cooldown_if_extreme(peer_ip, "idle_no_request");
    }

    pub(crate) fn note_l4_rejection(&self, peer_ip: IpAddr) {
        self.add_debt(peer_ip, 8);
        self.record_cluster_observed(
            peer_ip,
            "l4_admission_reject",
            "tcp",
            "connection_budget",
            8,
        );
        self.note_signal(8);
        self.cooldown_if_extreme(peer_ip, "l4_admission_reject");
    }

    pub(crate) fn note_http_request(&self, peer_ip: IpAddr) {
        self.add_debt(peer_ip, -3);
        self.decay_if_needed();
    }

    pub(crate) fn should_aggregate_event(&self, action: &str) -> bool {
        let mode = self.current_mode();
        if mode >= MODE_SURVIVAL {
            return true;
        }
        if mode >= MODE_UNDER_ATTACK {
            return matches!(action, "log" | "alert" | "respond" | "allow" | "block");
        }
        false
    }

    pub(crate) fn should_aggregate_security_event(&self, event: &SecurityEventRecord) -> bool {
        let global_pressure = self.should_aggregate_event(&event.action);
        let Some(peer_ip) = parse_event_ip(event) else {
            return global_pressure;
        };

        let observed = self.record_event_cluster_observed(peer_ip, event);
        let keep_sample = observed.count == 1 || observed.count % HOT_EVENT_SAMPLE_INTERVAL == 0;
        if keep_sample {
            return false;
        }

        let low_value_action = is_low_value_persistence_action(&event.action);
        if global_pressure {
            return low_value_action || self.current_mode() >= MODE_SURVIVAL;
        }

        low_value_action
            && (observed.count >= HOT_EVENT_CLUSTER_COUNT
                || observed.score >= HOT_EVENT_CLUSTER_SCORE)
    }

    pub(crate) fn note_security_event_aggregated(&self, event: &SecurityEventRecord) {
        self.aggregated_events.fetch_add(1, Ordering::Relaxed);
        if let Some(peer_ip) = parse_event_ip(event) {
            let parts = event_cluster_parts(event);
            self.record_cluster_aggregated(
                peer_ip,
                parts.attack_type,
                parts.transport,
                parts.reason,
                1,
            );
        } else {
            self.note_signal(1);
            return;
        }
        self.note_signal(1);
    }

    pub(crate) fn snapshot(&self) -> ResourceSentinelSnapshot {
        self.decay_if_needed();
        let mut high_debt_buckets = 0u64;
        let mut extreme_debt_buckets = 0u64;
        for bucket in self.connection_debt.iter() {
            let score = bucket.score.load(Ordering::Relaxed);
            if score >= DEBT_HIGH {
                high_debt_buckets += 1;
            }
            if score >= DEBT_EXTREME {
                extreme_debt_buckets += 1;
            }
        }

        ResourceSentinelSnapshot {
            mode: mode_label(self.mode.load(Ordering::Relaxed)).to_string(),
            attack_score: self.attack_score.load(Ordering::Relaxed),
            tracked_debt_buckets: self.connection_debt.len() as u64,
            high_debt_buckets,
            extreme_debt_buckets,
            tracked_attack_clusters: self.attack_clusters.len() as u64,
            active_cooldowns: self.active_cooldown_count(),
            pre_admission_rejections: self.pre_admission_rejections.load(Ordering::Relaxed),
            aggregated_events: self.aggregated_events.load(Ordering::Relaxed),
            top_attack_clusters: self.top_attack_clusters(8),
        }
    }

    pub(crate) fn apply_runtime_pressure(&self, pressure: &mut RuntimePressureSnapshot) {
        let mode = self.current_mode();
        if mode >= MODE_ELEVATED && matches!(pressure.level, "normal") {
            pressure.level = "elevated";
        }
        if mode >= MODE_UNDER_ATTACK && !matches!(pressure.level, "attack") {
            pressure.level = "high";
            pressure.drop_delay = true;
            pressure.trim_event_persistence = true;
            pressure.prefer_drop = true;
        }
        if mode >= MODE_SURVIVAL {
            pressure.level = "attack";
            pressure.defense_depth = "survival";
            pressure.drop_delay = true;
            pressure.trim_event_persistence = true;
            pressure.prefer_drop = true;
        }
    }

    fn current_mode(&self) -> u8 {
        self.decay_if_needed();
        self.mode.load(Ordering::Relaxed)
    }

    fn note_signal(&self, weight: u64) {
        self.decay_if_needed();
        let mut current = self.attack_score.load(Ordering::Relaxed);
        loop {
            let next = current.saturating_add(weight).min(SCORE_CAP);
            match self.attack_score.compare_exchange_weak(
                current,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    self.refresh_mode(next);
                    return;
                }
                Err(actual) => current = actual,
            }
        }
    }

    fn decay_if_needed(&self) {
        let now = now_millis();
        let last = self.last_decay_ms.load(Ordering::Relaxed);
        if now.saturating_sub(last) < 250 {
            return;
        }
        if self
            .last_decay_ms
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return;
        }

        let elapsed_quarters = now.saturating_sub(last) / 250;
        let decay = elapsed_quarters.saturating_mul(2).max(1);
        let current = self.attack_score.load(Ordering::Relaxed);
        let next = current.saturating_sub(decay);
        self.attack_score.store(next, Ordering::Relaxed);
        self.refresh_mode(next);
        self.prune_stale_debt(now);
    }

    fn refresh_mode(&self, score: u64) {
        let next = if score >= SCORE_SURVIVAL {
            MODE_SURVIVAL
        } else if score >= SCORE_UNDER_ATTACK {
            MODE_UNDER_ATTACK
        } else if score >= SCORE_ELEVATED {
            MODE_ELEVATED
        } else {
            MODE_NORMAL
        };
        let current = self.mode.load(Ordering::Relaxed);
        if next > current {
            self.last_escalation_ms
                .store(now_millis(), Ordering::Relaxed);
            self.mode.store(next, Ordering::Relaxed);
            return;
        }

        // Downgrade slowly so short attack pauses do not flap the gateway.
        let stable_for_ms =
            now_millis().saturating_sub(self.last_escalation_ms.load(Ordering::Relaxed));
        if next < current && stable_for_ms >= 10_000 {
            self.mode.store(next, Ordering::Relaxed);
            self.last_escalation_ms
                .store(now_millis(), Ordering::Relaxed);
        }
    }

    fn add_debt(&self, peer_ip: IpAddr, delta: i64) {
        let now = now_millis();
        for key in debt_keys(peer_ip) {
            let bucket = self
                .connection_debt
                .entry(key)
                .or_insert_with(|| DebtBucket {
                    score: AtomicI64::new(0),
                    last_seen_ms: AtomicU64::new(now),
                });
            bucket.last_seen_ms.store(now, Ordering::Relaxed);
            let mut current = bucket.score.load(Ordering::Relaxed);
            loop {
                let next = (current + delta).clamp(0, DEBT_CAP);
                match bucket.score.compare_exchange_weak(
                    current,
                    next,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => break,
                    Err(actual) => current = actual,
                }
            }
        }
    }

    fn debt_score(&self, peer_ip: IpAddr) -> i64 {
        let mut score = 0i64;
        for key in debt_keys(peer_ip) {
            if let Some(bucket) = self.connection_debt.get(&key) {
                score = score.max(bucket.score.load(Ordering::Relaxed));
            }
        }
        score
    }

    fn prune_stale_debt(&self, now: u64) {
        if self.connection_debt.len() <= 16_384 {
            return;
        }
        self.connection_debt.retain(|_, bucket| {
            let score = bucket.score.load(Ordering::Relaxed);
            let idle_ms = now.saturating_sub(bucket.last_seen_ms.load(Ordering::Relaxed));
            score >= DEBT_HIGH || idle_ms < 300_000
        });
        self.cooldowns
            .retain(|_, bucket| bucket.until_ms.load(Ordering::Relaxed) > now);
        self.attack_clusters.retain(|_, bucket| {
            let score = bucket.score.load(Ordering::Relaxed);
            let idle_ms = now.saturating_sub(bucket.last_seen_ms.load(Ordering::Relaxed));
            score >= 20 || idle_ms < 300_000
        });
    }

    fn record_cluster_observed(
        &self,
        peer_ip: IpAddr,
        attack_type: &'static str,
        transport: &str,
        reason: &'static str,
        score_delta: u64,
    ) {
        let bucket = self.cluster_bucket(peer_ip, attack_type, transport, reason);
        bucket.count.fetch_add(1, Ordering::Relaxed);
        bucket.score.fetch_add(score_delta, Ordering::Relaxed);
        bucket.last_seen_ms.store(now_millis(), Ordering::Relaxed);
    }

    fn record_event_cluster_observed(
        &self,
        peer_ip: IpAddr,
        event: &SecurityEventRecord,
    ) -> EventClusterObservation {
        let parts = event_cluster_parts(event);
        let bucket = self.cluster_bucket(peer_ip, parts.attack_type, parts.transport, parts.reason);
        let count = bucket.count.fetch_add(1, Ordering::Relaxed) + 1;
        let score =
            bucket.score.fetch_add(parts.score_delta, Ordering::Relaxed) + parts.score_delta;
        bucket.last_seen_ms.store(now_millis(), Ordering::Relaxed);
        EventClusterObservation { count, score }
    }

    fn record_cluster_admitted(
        &self,
        peer_ip: IpAddr,
        attack_type: &'static str,
        transport: &str,
        reason: &'static str,
        score_delta: u64,
    ) {
        let bucket = self.cluster_bucket(peer_ip, attack_type, transport, reason);
        bucket.admitted.fetch_add(1, Ordering::Relaxed);
        bucket.score.fetch_add(score_delta, Ordering::Relaxed);
        bucket.last_seen_ms.store(now_millis(), Ordering::Relaxed);
    }

    fn record_cluster_rejected(
        &self,
        peer_ip: IpAddr,
        attack_type: &'static str,
        transport: &str,
        reason: &str,
        score_delta: u64,
    ) {
        let bucket = self.cluster_bucket(peer_ip, attack_type, transport, reason);
        bucket.rejected.fetch_add(1, Ordering::Relaxed);
        bucket.score.fetch_add(score_delta, Ordering::Relaxed);
        bucket.last_seen_ms.store(now_millis(), Ordering::Relaxed);
    }

    fn record_cluster_aggregated(
        &self,
        peer_ip: IpAddr,
        attack_type: &'static str,
        transport: &str,
        reason: &str,
        score_delta: u64,
    ) {
        let bucket = self.cluster_bucket(peer_ip, attack_type, transport, reason);
        bucket.aggregated.fetch_add(1, Ordering::Relaxed);
        bucket.score.fetch_add(score_delta, Ordering::Relaxed);
        bucket.last_seen_ms.store(now_millis(), Ordering::Relaxed);
    }

    fn cluster_bucket(
        &self,
        peer_ip: IpAddr,
        attack_type: &str,
        transport: &str,
        reason: &str,
    ) -> dashmap::mapref::one::RefMut<'_, String, AttackClusterBucket> {
        let now = now_millis();
        let cluster = cluster_key(peer_ip);
        let key = format!("{cluster}\u{1f}{attack_type}\u{1f}{transport}\u{1f}{reason}");
        self.attack_clusters
            .entry(key)
            .or_insert_with(|| AttackClusterBucket {
                cluster: cluster.clone(),
                attack_type: attack_type.to_string(),
                transport: transport.to_string(),
                reason: reason.to_string(),
                sample_ip: peer_ip.to_string(),
                count: AtomicU64::new(0),
                admitted: AtomicU64::new(0),
                rejected: AtomicU64::new(0),
                aggregated: AtomicU64::new(0),
                score: AtomicU64::new(0),
                first_seen_ms: now,
                last_seen_ms: AtomicU64::new(now),
            })
    }

    fn top_attack_clusters(&self, limit: usize) -> Vec<ResourceSentinelClusterSnapshot> {
        let mut items = self
            .attack_clusters
            .iter()
            .map(|entry| {
                let bucket = entry.value();
                ResourceSentinelClusterSnapshot {
                    cluster: bucket.cluster.clone(),
                    attack_type: bucket.attack_type.clone(),
                    transport: bucket.transport.clone(),
                    reason: bucket.reason.clone(),
                    sample_ip: bucket.sample_ip.clone(),
                    count: bucket.count.load(Ordering::Relaxed),
                    admitted: bucket.admitted.load(Ordering::Relaxed),
                    rejected: bucket.rejected.load(Ordering::Relaxed),
                    aggregated: bucket.aggregated.load(Ordering::Relaxed),
                    score: bucket.score.load(Ordering::Relaxed),
                    first_seen_ms: bucket.first_seen_ms,
                    last_seen_ms: bucket.last_seen_ms.load(Ordering::Relaxed),
                }
            })
            .collect::<Vec<_>>();
        items.sort_by(|left, right| {
            right
                .score
                .cmp(&left.score)
                .then_with(|| right.count.cmp(&left.count))
                .then_with(|| right.last_seen_ms.cmp(&left.last_seen_ms))
        });
        items.truncate(limit);
        items
    }

    fn active_cooldown_reason(&self, peer_ip: IpAddr) -> Option<String> {
        let now = now_millis();
        for key in cooldown_keys(peer_ip) {
            if let Some(bucket) = self.cooldowns.get(&key) {
                if bucket.until_ms.load(Ordering::Relaxed) > now {
                    return Some(bucket.reason.clone());
                }
            }
        }
        None
    }

    fn active_cooldown_count(&self) -> u64 {
        let now = now_millis();
        self.cooldowns
            .iter()
            .filter(|entry| entry.until_ms.load(Ordering::Relaxed) > now)
            .count() as u64
    }

    fn cooldown_if_extreme(&self, peer_ip: IpAddr, reason: &'static str) {
        let debt = self.debt_score(peer_ip);
        if debt < DEBT_EXTREME {
            return;
        }
        let now = now_millis();
        self.set_cooldown(format!("ip:{peer_ip}"), now + IP_COOLDOWN_MS, reason);
        self.set_cooldown(
            format!("cluster:{}", cluster_key(peer_ip)),
            now + CLUSTER_COOLDOWN_MS,
            reason,
        );
    }

    fn set_cooldown(&self, key: String, until_ms: u64, reason: &'static str) {
        let bucket = self.cooldowns.entry(key).or_insert_with(|| CooldownBucket {
            until_ms: AtomicU64::new(until_ms),
            reason: reason.to_string(),
        });
        let mut current = bucket.until_ms.load(Ordering::Relaxed);
        while until_ms > current {
            match bucket.until_ms.compare_exchange_weak(
                current,
                until_ms,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => current = actual,
            }
        }
    }

    fn is_new_cluster(&self, peer_ip: IpAddr) -> bool {
        !self
            .connection_debt
            .contains_key(&format!("cluster:{}", cluster_key(peer_ip)))
    }

    fn consume_new_cluster_budget(&self, mode: u8) -> bool {
        let budget = if mode >= MODE_SURVIVAL {
            SURVIVAL_NEW_CLUSTER_BUDGET
        } else {
            UNDER_ATTACK_NEW_CLUSTER_BUDGET
        };
        let now_window = window_start(now_millis());
        let current_window = self.new_cluster_budget_window_ms.load(Ordering::Relaxed);
        if now_window != current_window
            && self
                .new_cluster_budget_window_ms
                .compare_exchange(
                    current_window,
                    now_window,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                )
                .is_ok()
        {
            self.new_cluster_budget_used.store(0, Ordering::Relaxed);
        }
        self.new_cluster_budget_used
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                (current < budget).then_some(current + 1)
            })
            .is_ok()
    }
}

impl Default for ResourceSentinel {
    fn default() -> Self {
        Self::new()
    }
}

impl WafContext {
    pub(crate) fn resource_sentinel_snapshot(&self) -> ResourceSentinelSnapshot {
        self.resource_sentinel.snapshot()
    }

    pub(crate) fn adaptive_enqueue_security_event(
        &self,
        store: &SqliteStore,
        event: SecurityEventRecord,
        trigger: &'static str,
    ) {
        if self
            .resource_sentinel
            .should_aggregate_security_event(&event)
        {
            self.resource_sentinel
                .note_security_event_aggregated(&event);
            store.enqueue_security_event_aggregated(event, trigger);
        } else {
            store.enqueue_security_event(event);
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct EventClusterObservation {
    count: u64,
    score: u64,
}

#[derive(Debug, Clone, Copy)]
struct EventClusterParts {
    attack_type: &'static str,
    transport: &'static str,
    reason: &'static str,
    score_delta: u64,
}

fn debt_keys(peer_ip: IpAddr) -> [String; 2] {
    [
        format!("ip:{peer_ip}"),
        format!("cluster:{}", cluster_key(peer_ip)),
    ]
}

fn cooldown_keys(peer_ip: IpAddr) -> [String; 2] {
    debt_keys(peer_ip)
}

fn cluster_key(peer_ip: IpAddr) -> String {
    match peer_ip {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            Ipv4Addr::new(a, b, c, 0).to_string() + "/24"
        }
        IpAddr::V6(ip) => {
            let segments = ip.segments();
            Ipv6Addr::new(
                segments[0],
                segments[1],
                segments[2],
                segments[3],
                0,
                0,
                0,
                0,
            )
            .to_string()
                + "/64"
        }
    }
}

fn mode_label(mode: u8) -> &'static str {
    match mode {
        MODE_SURVIVAL => "survival",
        MODE_UNDER_ATTACK => "under_attack",
        MODE_ELEVATED => "elevated",
        _ => "normal",
    }
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

fn window_start(now_ms: u64) -> u64 {
    now_ms / NEW_CLUSTER_BUDGET_WINDOW_MS * NEW_CLUSTER_BUDGET_WINDOW_MS
}

fn parse_event_ip(event: &SecurityEventRecord) -> Option<IpAddr> {
    event.source_ip.parse::<IpAddr>().ok()
}

fn is_low_value_persistence_action(action: &str) -> bool {
    matches!(action, "log" | "alert" | "respond" | "allow" | "block")
}

fn event_cluster_parts(event: &SecurityEventRecord) -> EventClusterParts {
    let reason = event.reason.to_ascii_lowercase();
    let protocol = event.protocol.to_ascii_lowercase();
    let transport = if protocol.contains("udp") || protocol.contains("quic") {
        "udp"
    } else if protocol.contains("tls") || reason.contains("tls") {
        "tls"
    } else if event.layer == "L7" {
        "http"
    } else {
        "tcp"
    };

    let (attack_type, reason_family, base_score) =
        if reason.contains("tls") && (reason.contains("timeout") || reason.contains("timed out")) {
            ("slow_tls_handshake", "timeout", 10)
        } else if reason.contains("tls") && reason.contains("handshake") {
            ("tls_handshake_failure", "handshake_error", 4)
        } else if reason.contains("no request")
            || reason.contains("no_request")
            || reason.contains("idle")
            || reason.contains("slow attack")
        {
            ("idle_no_request", "no_request_timeout", 8)
        } else if reason.contains("rate limit")
            || reason.contains("admission")
            || reason.contains("connection budget")
            || reason.contains("bucket")
        {
            ("l4_admission_reject", "connection_budget", 8)
        } else if event.provider.as_deref() == Some("safeline") {
            ("provider_intercept", "safeline", 6)
        } else if event.layer == "L7" {
            ("l7_security_event", "policy_match", 3)
        } else {
            ("l4_security_event", "policy_match", 3)
        };

    let action_score = match event.action.as_str() {
        "drop" => 8,
        "block" => 6,
        "respond" => 4,
        "alert" => 2,
        _ => 1,
    };

    EventClusterParts {
        attack_type,
        transport,
        reason: reason_family,
        score_delta: base_score + action_score,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeated_timeouts_immediately_escalate_and_reject_debt_sources() {
        let sentinel = ResourceSentinel::new();
        let ip: IpAddr = "203.0.113.9".parse().unwrap();

        for _ in 0..20 {
            sentinel.note_tls_timeout(ip);
        }

        let snapshot = sentinel.snapshot();
        assert_eq!(snapshot.mode, "survival");
        assert!(snapshot.attack_score >= SCORE_SURVIVAL);
        assert!(snapshot.high_debt_buckets >= 1);

        let decision = sentinel.admit_connection(ip, "tls", 128, 0);
        assert!(!decision.allow);
        assert!(decision
            .reason
            .as_deref()
            .unwrap_or_default()
            .contains("resource sentinel rejected tls connection"));
    }

    #[test]
    fn successful_http_requests_pay_down_connection_debt() {
        let sentinel = ResourceSentinel::new();
        let ip: IpAddr = "203.0.113.10".parse().unwrap();

        for _ in 0..8 {
            sentinel.note_tls_failure(ip);
        }
        let before = sentinel.debt_score(ip);
        for _ in 0..5 {
            sentinel.note_http_request(ip);
        }

        assert!(sentinel.debt_score(ip) < before);
    }

    #[test]
    fn attack_clusters_group_by_subnet_and_attack_type() {
        let sentinel = ResourceSentinel::new();
        let first: IpAddr = "203.0.113.10".parse().unwrap();
        let second: IpAddr = "203.0.113.11".parse().unwrap();

        sentinel.note_tls_timeout(first);
        sentinel.note_tls_timeout(second);
        sentinel.note_l4_rejection(second);

        let snapshot = sentinel.snapshot();
        assert_eq!(snapshot.tracked_attack_clusters, 2);
        assert_eq!(snapshot.top_attack_clusters[0].cluster, "203.0.113.0/24");
        assert_eq!(
            snapshot.top_attack_clusters[0].attack_type,
            "slow_tls_handshake"
        );
        assert_eq!(snapshot.top_attack_clusters[0].count, 2);
        assert_eq!(
            snapshot.top_attack_clusters[1].attack_type,
            "l4_admission_reject"
        );
    }

    #[test]
    fn survival_limits_brand_new_clusters_before_debt_exists() {
        let sentinel = ResourceSentinel::new();
        for index in 1..=20 {
            sentinel.note_tls_timeout(format!("198.51.100.{index}").parse().unwrap());
        }
        assert_eq!(sentinel.snapshot().mode, "survival");

        let mut allowed = 0usize;
        let mut rejected = 0usize;
        for index in 1..=32 {
            let ip: IpAddr = format!("10.0.{index}.1").parse().unwrap();
            let decision = sentinel.admit_connection(ip, "tls", 128, 0);
            if decision.allow {
                allowed += 1;
            } else {
                rejected += 1;
            }
        }

        assert_eq!(allowed, SURVIVAL_NEW_CLUSTER_BUDGET as usize);
        assert_eq!(rejected, 32 - SURVIVAL_NEW_CLUSTER_BUDGET as usize);
    }

    #[test]
    fn extreme_debt_enters_ttl_cooldown() {
        let sentinel = ResourceSentinel::new();
        let ip: IpAddr = "203.0.113.55".parse().unwrap();

        for _ in 0..10 {
            sentinel.note_tls_timeout(ip);
        }

        let decision = sentinel.admit_connection(ip, "tls", 128, 0);
        assert!(!decision.allow);
        assert!(decision
            .reason
            .as_deref()
            .unwrap_or_default()
            .contains("cooldown"));
        assert!(sentinel.snapshot().active_cooldowns >= 1);
    }

    #[test]
    fn hot_security_event_clusters_are_aggregated_but_keep_samples() {
        let sentinel = ResourceSentinel::new();
        let event = SecurityEventRecord::now(
            "L4",
            "alert",
            "tls handshake timed out before first request",
            "203.0.113.77",
            "192.0.2.10",
            44321,
            443,
            "TCP",
        );

        assert!(!sentinel.should_aggregate_security_event(&event));
        let mut aggregated = 0u64;
        let mut sampled = 1u64;
        for _ in 0..48 {
            if sentinel.should_aggregate_security_event(&event) {
                sentinel.note_security_event_aggregated(&event);
                aggregated += 1;
            } else {
                sampled += 1;
            }
        }

        assert!(aggregated > 0);
        assert!(sampled > 1);
        let snapshot = sentinel.snapshot();
        let cluster = snapshot
            .top_attack_clusters
            .iter()
            .find(|cluster| cluster.attack_type == "slow_tls_handshake")
            .expect("hot TLS event cluster should be tracked");
        assert_eq!(cluster.cluster, "203.0.113.0/24");
        assert!(cluster.count >= HOT_EVENT_CLUSTER_COUNT);
        assert!(cluster.aggregated > 0);
    }
}
