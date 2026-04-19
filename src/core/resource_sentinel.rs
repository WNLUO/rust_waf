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

#[derive(Debug)]
pub(crate) struct ResourceSentinel {
    mode: AtomicU8,
    attack_score: AtomicU64,
    last_decay_ms: AtomicU64,
    last_escalation_ms: AtomicU64,
    connection_debt: DashMap<String, DebtBucket>,
    pre_admission_rejections: AtomicU64,
    aggregated_events: AtomicU64,
}

#[derive(Debug)]
struct DebtBucket {
    score: AtomicI64,
    last_seen_ms: AtomicU64,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct ResourceSentinelSnapshot {
    pub mode: String,
    pub attack_score: u64,
    pub tracked_debt_buckets: u64,
    pub high_debt_buckets: u64,
    pub extreme_debt_buckets: u64,
    pub pre_admission_rejections: u64,
    pub aggregated_events: u64,
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
        let permits_low = available_connection_permits <= 4;
        let storage_hot = storage_queue_usage_percent >= 90;
        let reject = match mode {
            MODE_SURVIVAL => debt >= DEBT_HIGH || (permits_low && debt >= 25) || storage_hot,
            MODE_UNDER_ATTACK => debt >= DEBT_EXTREME || (permits_low && debt >= 45),
            MODE_ELEVATED => permits_low && debt >= DEBT_EXTREME,
            _ => false,
        };

        if reject {
            self.pre_admission_rejections
                .fetch_add(1, Ordering::Relaxed);
            self.note_signal(18);
            return AdmissionDecision {
                allow: false,
                reason: Some(format!(
                    "resource sentinel rejected {transport} connection: mode={} debt={} available_connection_permits={} storage_queue={}%",
                    mode_label(mode),
                    debt,
                    available_connection_permits,
                    storage_queue_usage_percent
                )),
            };
        }

        AdmissionDecision {
            allow: true,
            reason: None,
        }
    }

    pub(crate) fn note_tls_timeout(&self, peer_ip: IpAddr) {
        self.add_debt(peer_ip, 12);
        self.note_signal(10);
    }

    pub(crate) fn note_tls_failure(&self, peer_ip: IpAddr) {
        self.add_debt(peer_ip, 6);
        self.note_signal(4);
    }

    pub(crate) fn note_no_request_timeout(&self, peer_ip: IpAddr) {
        self.add_debt(peer_ip, 10);
        self.note_signal(8);
    }

    pub(crate) fn note_l4_rejection(&self, peer_ip: IpAddr) {
        self.add_debt(peer_ip, 8);
        self.note_signal(8);
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

    pub(crate) fn note_aggregated_event(&self) {
        self.aggregated_events.fetch_add(1, Ordering::Relaxed);
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
            pre_admission_rejections: self.pre_admission_rejections.load(Ordering::Relaxed),
            aggregated_events: self.aggregated_events.load(Ordering::Relaxed),
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
        if self.resource_sentinel.should_aggregate_event(&event.action) {
            self.resource_sentinel.note_aggregated_event();
            store.enqueue_security_event_aggregated(event, trigger);
        } else {
            store.enqueue_security_event(event);
        }
    }
}

fn debt_keys(peer_ip: IpAddr) -> [String; 2] {
    [
        format!("ip:{peer_ip}"),
        format!("cluster:{}", cluster_key(peer_ip)),
    ]
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
}
