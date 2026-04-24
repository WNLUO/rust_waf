use super::{RuntimePressureSnapshot, WafContext};
use crate::storage::{SecurityEventRecord, SqliteStore};
use dashmap::DashMap;
use serde::Serialize;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicI64, AtomicU64, AtomicU8, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const MODE_NORMAL: u8 = 0;
const MODE_ELEVATED: u8 = 1;
const MODE_UNDER_ATTACK: u8 = 2;
const MODE_SURVIVAL: u8 = 3;
const ATTACK_PHASE_NORMAL: u8 = 0;
const ATTACK_PHASE_STARTED: u8 = 1;
const ATTACK_PHASE_SUSTAINED: u8 = 2;
const ATTACK_PHASE_MITIGATING: u8 = 3;
const ATTACK_PHASE_ENDED: u8 = 4;
const DEFENSE_OUTCOME_UNKNOWN: u8 = 0;
const DEFENSE_OUTCOME_EFFECTIVE: u8 = 1;
const DEFENSE_OUTCOME_WEAK: u8 = 2;
const DEFENSE_OUTCOME_HARMFUL: u8 = 3;
const DEFENSE_OUTCOME_RECOVERED: u8 = 4;
const DEFENSE_ACTION_TLS_PRE_ADMISSION: &str = "tls_pre_admission_cooldown";
const DEFENSE_ACTION_CLUSTER_CONNECTION: &str = "cluster_connection_cooldown";

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
const HOT_CLUSTER_DEFENSE_MIN_COUNT: u64 = 8;
const HOT_CLUSTER_DEFENSE_COUNT: u64 = 24;
const HOT_CLUSTER_DEFENSE_SCORE: u64 = 120;
const HOT_CLUSTER_DEFENSE_COOLDOWN_MS: u64 = 20_000;
const SURVIVAL_CLUSTER_DEFENSE_COOLDOWN_MS: u64 = 45_000;
const DEFENSE_EFFECT_EVAL_INTERVAL_MS: u64 = 1_000;
const DEFENSE_EFFECT_EXTEND_MS: u64 = 10_000;
const DEFENSE_EFFECT_SURVIVAL_EXTEND_MS: u64 = 30_000;
const DEFENSE_EFFECT_MAX_LIFETIME_MS: u64 = 120_000;
const DEFENSE_EFFECT_RELAX_TO_MS: u64 = 2_000;
const DEFENSE_EFFECT_REJECTION_DELTA: u64 = 3;
const ATTACK_AUDIT_MIN_INTERVAL_MS: u64 = 10_000;
const ATTACK_AUDIT_REPEAT_COOLDOWN_MS: u64 = 60_000;
const ATTACK_SESSION_PERSIST_INTERVAL_MS: u64 = 5_000;
const FAST_PATH_STORAGE_QUEUE_PERCENT: u64 = 90;

#[derive(Debug)]
pub(crate) struct ResourceSentinel {
    mode: AtomicU8,
    attack_score: AtomicU64,
    last_decay_ms: AtomicU64,
    last_escalation_ms: AtomicU64,
    connection_debt: DashMap<String, DebtBucket>,
    cooldowns: DashMap<String, CooldownBucket>,
    attack_clusters: DashMap<String, AttackClusterBucket>,
    defense_memory: DashMap<String, DefenseMemoryBucket>,
    defense_decisions: DashMap<String, DefenseDecisionBucket>,
    new_cluster_budget_window_ms: AtomicU64,
    new_cluster_budget_used: AtomicU64,
    pre_admission_rejections: AtomicU64,
    aggregated_events: AtomicU64,
    automated_defense_actions: AtomicU64,
    automated_defense_extensions: AtomicU64,
    automated_defense_relaxations: AtomicU64,
    automated_defense_memory_hits: AtomicU64,
    automated_audit_events: AtomicU64,
    last_attack_audit_ms: AtomicU64,
    last_attack_audit_signature: AtomicU64,
    attack_phase: AtomicU8,
    attack_phase_since_ms: AtomicU64,
    attack_session_id: AtomicU64,
    attack_session_started_ms: AtomicU64,
    attack_session_ended_ms: AtomicU64,
    attack_session_peak_score: AtomicU64,
    attack_session_start_rejections: AtomicU64,
    attack_session_start_aggregated_events: AtomicU64,
    attack_session_start_defense_actions: AtomicU64,
    attack_session_start_defense_extensions: AtomicU64,
    attack_session_start_defense_relaxations: AtomicU64,
    attack_session_start_audit_events: AtomicU64,
    last_runtime_storage_queue_percent: AtomicU64,
    last_runtime_pressure_level: AtomicU8,
    fast_path_activations: AtomicU64,
    last_attack_session_persist_ms: AtomicU64,
    last_persisted_attack_session_id: AtomicU64,
}

#[derive(Debug)]
struct DebtBucket {
    score: AtomicI64,
    last_seen_ms: AtomicU64,
}

#[derive(Debug)]
struct CooldownBucket {
    until_ms: AtomicU64,
    created_ms: u64,
    last_evaluated_ms: AtomicU64,
    last_rejections: AtomicU64,
    last_attack_score: AtomicU64,
    extensions: AtomicU64,
    relaxations: AtomicU64,
    attack_type: String,
    action: String,
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

#[derive(Debug)]
struct DefenseMemoryBucket {
    preferred_action: String,
    effective_score: AtomicU64,
    ineffective_score: AtomicU64,
    weak_score: AtomicU64,
    harmful_score: AtomicU64,
    last_outcome: AtomicU8,
    last_rejection_delta: AtomicU64,
    last_score_delta: AtomicI64,
    last_seen_ms: AtomicU64,
}

#[derive(Debug, Clone)]
struct DefenseActionMemorySnapshot {
    preferred_action: String,
    effective_score: u64,
    ineffective_score: u64,
    weak_score: u64,
    harmful_score: u64,
    last_outcome: u8,
}

#[derive(Debug)]
struct DefenseDecisionBucket {
    attack_type: String,
    selected_action: String,
    default_action: String,
    reason: String,
    mode: String,
    memory_outcome: String,
    confidence: AtomicU64,
    effective_score: AtomicU64,
    ineffective_score: AtomicU64,
    weak_score: AtomicU64,
    harmful_score: AtomicU64,
    used_memory: bool,
    switched_action: bool,
    observed_at_ms: AtomicU64,
}

#[derive(Debug, Clone)]
struct DefenseActionSelection {
    action: Option<&'static str>,
    default_action: Option<&'static str>,
    reason: &'static str,
    used_memory: bool,
    switched_action: bool,
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
    pub automated_defense_actions: u64,
    pub automated_defense_extensions: u64,
    pub automated_defense_relaxations: u64,
    pub automated_defense_memory_hits: u64,
    pub automated_audit_events: u64,
    pub top_attack_clusters: Vec<ResourceSentinelClusterSnapshot>,
    pub defense_action_effects: Vec<ResourceSentinelDefenseActionEffect>,
    pub defense_decision_traces: Vec<ResourceSentinelDefenseDecisionTrace>,
    pub ingress_gap_analysis: ResourceSentinelIngressGapAnalysis,
    pub resource_pressure_feedback: ResourceSentinelResourcePressureFeedback,
    pub attack_migrations: Vec<ResourceSentinelAttackMigration>,
    pub attack_report_preview: Option<ResourceSentinelAttackReport>,
    pub attack_diagnosis: ResourceSentinelAttackDiagnosis,
    pub attack_lifecycle: ResourceSentinelAttackLifecycle,
    pub attack_session: ResourceSentinelAttackSession,
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

#[derive(Debug, Clone, Serialize, Default)]
pub struct ResourceSentinelDefenseActionEffect {
    pub attack_type: String,
    pub preferred_action: String,
    pub effective_score: u64,
    pub ineffective_score: u64,
    pub weak_score: u64,
    pub harmful_score: u64,
    pub confidence: u64,
    pub last_outcome: String,
    pub last_rejection_delta: u64,
    pub last_score_delta: i64,
    pub last_seen_ms: u64,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct ResourceSentinelDefenseDecisionTrace {
    pub attack_type: String,
    pub selected_action: String,
    pub default_action: String,
    pub reason: String,
    pub mode: String,
    pub memory_outcome: String,
    pub confidence: u64,
    pub effective_score: u64,
    pub ineffective_score: u64,
    pub weak_score: u64,
    pub harmful_score: u64,
    pub used_memory: bool,
    pub switched_action: bool,
    pub observed_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct ResourceSentinelIngressGapAnalysis {
    pub cdn_observed_requests: Option<u64>,
    pub rust_observed_intercepts: u64,
    pub estimated_outer_layer_absorption_ratio: Option<u64>,
    pub likely_absorption_layer: String,
    pub confidence: String,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct ResourceSentinelResourcePressureFeedback {
    pub pressure_level: String,
    pub storage_queue_usage_percent: u64,
    pub fast_path_activations: u64,
    pub resource_outcome: String,
    pub scoring_hint: String,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct ResourceSentinelAttackMigration {
    pub from_cluster: String,
    pub to_cluster: String,
    pub from_attack_type: String,
    pub to_attack_type: String,
    pub detected_at_ms: u64,
    pub reason: String,
    pub confidence: String,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct ResourceSentinelAttackReport {
    pub session_id: u64,
    pub generated_at_ms: u64,
    pub summary: String,
    pub what_worked: Vec<String>,
    pub what_was_weak: Vec<String>,
    pub what_was_harmful: Vec<String>,
    pub cdn_rust_gap_analysis: String,
    pub resource_pressure_summary: String,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResourceSentinelPersistenceSnapshot {
    pub session: ResourceSentinelAttackSession,
    pub lifecycle: ResourceSentinelAttackLifecycle,
    pub diagnosis: ResourceSentinelAttackDiagnosis,
    pub top_clusters: Vec<ResourceSentinelClusterSnapshot>,
    pub defense_effects: Vec<ResourceSentinelDefenseActionEffect>,
    pub decision_traces: Vec<ResourceSentinelDefenseDecisionTrace>,
    pub ingress_gap_analysis: ResourceSentinelIngressGapAnalysis,
    pub resource_pressure_feedback: ResourceSentinelResourcePressureFeedback,
    pub attack_migrations: Vec<ResourceSentinelAttackMigration>,
    pub attack_report: Option<ResourceSentinelAttackReport>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct ResourceSentinelDefenseMemoryExport {
    pub attack_type: String,
    pub preferred_action: String,
    pub effective_score: u64,
    pub ineffective_score: u64,
    pub weak_score: u64,
    pub harmful_score: u64,
    pub last_outcome: String,
    pub last_rejection_delta: u64,
    pub last_score_delta: i64,
    pub last_seen_ms: u64,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct ResourceSentinelAttackDiagnosis {
    pub severity: String,
    pub primary_pressure: String,
    pub summary: String,
    pub active_defense: String,
    pub recommended_next_action: String,
    pub evidence: Vec<String>,
    pub top_cluster: Option<ResourceSentinelClusterSnapshot>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct ResourceSentinelAttackLifecycle {
    pub phase: String,
    pub previous_phase: String,
    pub phase_since_ms: u64,
    pub transitioned: bool,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct ResourceSentinelAttackSession {
    pub session_id: u64,
    pub phase: String,
    pub started_at_ms: u64,
    pub ended_at_ms: Option<u64>,
    pub duration_ms: u64,
    pub peak_severity: String,
    pub peak_attack_score: u64,
    pub primary_pressure: String,
    pub top_clusters: Vec<ResourceSentinelClusterSnapshot>,
    pub defense_actions: u64,
    pub defense_extensions: u64,
    pub defense_relaxations: u64,
    pub audit_event_count: u64,
    pub pre_admission_rejections: u64,
    pub aggregated_events: u64,
    pub final_outcome: String,
    pub summary: String,
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
            defense_memory: DashMap::new(),
            defense_decisions: DashMap::new(),
            new_cluster_budget_window_ms: AtomicU64::new(window_start(now)),
            new_cluster_budget_used: AtomicU64::new(0),
            pre_admission_rejections: AtomicU64::new(0),
            aggregated_events: AtomicU64::new(0),
            automated_defense_actions: AtomicU64::new(0),
            automated_defense_extensions: AtomicU64::new(0),
            automated_defense_relaxations: AtomicU64::new(0),
            automated_defense_memory_hits: AtomicU64::new(0),
            automated_audit_events: AtomicU64::new(0),
            last_attack_audit_ms: AtomicU64::new(0),
            last_attack_audit_signature: AtomicU64::new(0),
            attack_phase: AtomicU8::new(ATTACK_PHASE_NORMAL),
            attack_phase_since_ms: AtomicU64::new(now),
            attack_session_id: AtomicU64::new(0),
            attack_session_started_ms: AtomicU64::new(0),
            attack_session_ended_ms: AtomicU64::new(0),
            attack_session_peak_score: AtomicU64::new(0),
            attack_session_start_rejections: AtomicU64::new(0),
            attack_session_start_aggregated_events: AtomicU64::new(0),
            attack_session_start_defense_actions: AtomicU64::new(0),
            attack_session_start_defense_extensions: AtomicU64::new(0),
            attack_session_start_defense_relaxations: AtomicU64::new(0),
            attack_session_start_audit_events: AtomicU64::new(0),
            last_runtime_storage_queue_percent: AtomicU64::new(0),
            last_runtime_pressure_level: AtomicU8::new(0),
            fast_path_activations: AtomicU64::new(0),
            last_attack_session_persist_ms: AtomicU64::new(0),
            last_persisted_attack_session_id: AtomicU64::new(0),
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
        if let Some(reason) = self.active_cooldown_reason(peer_ip, transport) {
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

        let mode = mode_label(self.mode.load(Ordering::Relaxed)).to_string();
        let attack_score = self.attack_score.load(Ordering::Relaxed);
        let tracked_debt_buckets = self.connection_debt.len() as u64;
        let active_cooldowns = self.active_cooldown_count();
        let pre_admission_rejections = self.pre_admission_rejections.load(Ordering::Relaxed);
        let aggregated_events = self.aggregated_events.load(Ordering::Relaxed);
        let automated_defense_actions = self.automated_defense_actions.load(Ordering::Relaxed);
        let automated_defense_extensions =
            self.automated_defense_extensions.load(Ordering::Relaxed);
        let automated_defense_relaxations =
            self.automated_defense_relaxations.load(Ordering::Relaxed);
        let automated_defense_memory_hits =
            self.automated_defense_memory_hits.load(Ordering::Relaxed);
        let automated_audit_events = self.automated_audit_events.load(Ordering::Relaxed);
        let top_attack_clusters = self.top_attack_clusters(8);
        let defense_action_effects = self.defense_action_effects(8);
        let defense_decision_traces = self.defense_decision_traces(8);
        let ingress_gap_analysis = build_ingress_gap_analysis(
            pre_admission_rejections,
            aggregated_events,
            &top_attack_clusters,
            self.last_runtime_storage_queue_percent
                .load(Ordering::Relaxed),
        );
        let resource_pressure_feedback = build_resource_pressure_feedback(
            self.last_runtime_pressure_level.load(Ordering::Relaxed),
            self.last_runtime_storage_queue_percent
                .load(Ordering::Relaxed),
            self.fast_path_activations.load(Ordering::Relaxed),
            attack_score,
        );
        let attack_migrations =
            build_attack_migrations(attack_score, &top_attack_clusters, now_millis());
        let attack_diagnosis = build_attack_diagnosis(
            &mode,
            attack_score,
            active_cooldowns,
            pre_admission_rejections,
            aggregated_events,
            automated_defense_actions,
            automated_defense_extensions,
            automated_defense_relaxations,
            automated_defense_memory_hits,
            &top_attack_clusters,
            &defense_action_effects,
            &defense_decision_traces,
        );
        let attack_lifecycle = self.update_attack_lifecycle(&attack_diagnosis);
        let attack_session = self.attack_session_snapshot(
            attack_score,
            pre_admission_rejections,
            aggregated_events,
            automated_defense_actions,
            automated_defense_extensions,
            automated_defense_relaxations,
            automated_audit_events,
            &attack_diagnosis,
            &attack_lifecycle,
            &top_attack_clusters,
        );
        let attack_report_preview = build_attack_report_preview(
            &attack_session,
            &defense_action_effects,
            &defense_decision_traces,
            &ingress_gap_analysis,
            &resource_pressure_feedback,
            &attack_migrations,
        );

        ResourceSentinelSnapshot {
            mode,
            attack_score,
            tracked_debt_buckets,
            high_debt_buckets,
            extreme_debt_buckets,
            tracked_attack_clusters: self.attack_clusters.len() as u64,
            active_cooldowns,
            pre_admission_rejections,
            aggregated_events,
            automated_defense_actions,
            automated_defense_extensions,
            automated_defense_relaxations,
            automated_defense_memory_hits,
            automated_audit_events,
            top_attack_clusters,
            defense_action_effects,
            defense_decision_traces,
            ingress_gap_analysis,
            resource_pressure_feedback,
            attack_migrations,
            attack_report_preview,
            attack_diagnosis,
            attack_lifecycle,
            attack_session,
        }
    }

    pub(crate) fn apply_runtime_pressure(&self, pressure: &mut RuntimePressureSnapshot) {
        let mode = self.current_mode();
        self.last_runtime_storage_queue_percent
            .store(pressure.storage_queue_usage_percent, Ordering::Relaxed);
        self.last_runtime_pressure_level
            .store(pressure_level_code(pressure.level), Ordering::Relaxed);
        if pressure.storage_queue_usage_percent >= FAST_PATH_STORAGE_QUEUE_PERCENT
            || matches!(pressure.level, "attack")
        {
            self.fast_path_activations.fetch_add(1, Ordering::Relaxed);
            self.note_signal(12);
        }
        if mode >= MODE_ELEVATED && matches!(pressure.level, "normal") {
            pressure.level = "elevated";
        }
        if mode >= MODE_UNDER_ATTACK && !matches!(pressure.level, "attack") {
            pressure.level = "high";
            pressure.drop_delay = true;
            pressure.trim_event_persistence = true;
        }
        if mode >= MODE_SURVIVAL {
            pressure.level = "attack";
            pressure.defense_depth = "survival";
            pressure.drop_delay = true;
            pressure.trim_event_persistence = true;
            pressure.prefer_drop = pressure.storage_queue_usage_percent >= 95
                || (pressure.cpu_pressure_score >= 3
                    && pressure.storage_queue_usage_percent >= FAST_PATH_STORAGE_QUEUE_PERCENT);
        }
    }

    pub(crate) fn maybe_persistence_snapshot(
        &self,
        force: bool,
    ) -> Option<ResourceSentinelPersistenceSnapshot> {
        let now = now_millis();
        let last = self.last_attack_session_persist_ms.load(Ordering::Relaxed);
        if !force && now.saturating_sub(last) < ATTACK_SESSION_PERSIST_INTERVAL_MS {
            return None;
        }
        let snapshot = self.snapshot();
        if snapshot.attack_session.session_id == 0 {
            return None;
        }
        let already_final = snapshot.attack_lifecycle.phase == "ended"
            && self
                .last_persisted_attack_session_id
                .load(Ordering::Relaxed)
                == snapshot.attack_session.session_id;
        if !force
            && already_final
            && snapshot.attack_session.ended_at_ms.is_some()
            && now.saturating_sub(last) < ATTACK_AUDIT_REPEAT_COOLDOWN_MS
        {
            return None;
        }
        if self
            .last_attack_session_persist_ms
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
            && !force
        {
            return None;
        }
        if snapshot.attack_session.ended_at_ms.is_some() {
            self.last_persisted_attack_session_id
                .store(snapshot.attack_session.session_id, Ordering::Relaxed);
        }
        Some(ResourceSentinelPersistenceSnapshot {
            session: snapshot.attack_session,
            lifecycle: snapshot.attack_lifecycle,
            diagnosis: snapshot.attack_diagnosis,
            top_clusters: snapshot.top_attack_clusters,
            defense_effects: snapshot.defense_action_effects,
            decision_traces: snapshot.defense_decision_traces,
            ingress_gap_analysis: snapshot.ingress_gap_analysis,
            resource_pressure_feedback: snapshot.resource_pressure_feedback,
            attack_migrations: snapshot.attack_migrations,
            attack_report: snapshot.attack_report_preview,
        })
    }

    pub(crate) fn defense_memory_exports(&self) -> Vec<ResourceSentinelDefenseMemoryExport> {
        self.defense_memory
            .iter()
            .map(|entry| {
                let bucket = entry.value();
                ResourceSentinelDefenseMemoryExport {
                    attack_type: entry.key().clone(),
                    preferred_action: bucket.preferred_action.clone(),
                    effective_score: bucket.effective_score.load(Ordering::Relaxed),
                    ineffective_score: bucket.ineffective_score.load(Ordering::Relaxed),
                    weak_score: bucket.weak_score.load(Ordering::Relaxed),
                    harmful_score: bucket.harmful_score.load(Ordering::Relaxed),
                    last_outcome: defense_outcome_label(
                        bucket.last_outcome.load(Ordering::Relaxed),
                    )
                    .to_string(),
                    last_rejection_delta: bucket.last_rejection_delta.load(Ordering::Relaxed),
                    last_score_delta: bucket.last_score_delta.load(Ordering::Relaxed),
                    last_seen_ms: bucket.last_seen_ms.load(Ordering::Relaxed),
                }
            })
            .collect()
    }

    pub(crate) fn restore_defense_memory(
        &self,
        attack_type: &str,
        preferred_action: &str,
        effective_score: u64,
        ineffective_score: u64,
        weak_score: u64,
        harmful_score: u64,
        last_outcome: &str,
        last_rejection_delta: u64,
        last_score_delta: i64,
        last_seen_ms: u64,
    ) {
        let outcome = defense_outcome_code(last_outcome);
        self.defense_memory.insert(
            attack_type.to_string(),
            DefenseMemoryBucket {
                preferred_action: preferred_action.to_string(),
                effective_score: AtomicU64::new(effective_score),
                ineffective_score: AtomicU64::new(ineffective_score),
                weak_score: AtomicU64::new(weak_score),
                harmful_score: AtomicU64::new(harmful_score),
                last_outcome: AtomicU8::new(outcome),
                last_rejection_delta: AtomicU64::new(last_rejection_delta),
                last_score_delta: AtomicI64::new(last_score_delta),
                last_seen_ms: AtomicU64::new(last_seen_ms),
            },
        );
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
        self.evaluate_defense_effects(now);
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
        self.defense_memory.retain(|_, bucket| {
            now.saturating_sub(bucket.last_seen_ms.load(Ordering::Relaxed)) < 600_000
        });
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
        let count = bucket.count.fetch_add(1, Ordering::Relaxed) + 1;
        let score = bucket.score.fetch_add(score_delta, Ordering::Relaxed) + score_delta;
        bucket.last_seen_ms.store(now_millis(), Ordering::Relaxed);
        drop(bucket);
        self.maybe_activate_hot_cluster_defense(peer_ip, attack_type, count, score);
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
        drop(bucket);
        self.maybe_activate_hot_cluster_defense(peer_ip, parts.attack_type, count, score);
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
        let count = bucket.count.load(Ordering::Relaxed);
        let score = bucket.score.fetch_add(score_delta, Ordering::Relaxed) + score_delta;
        bucket.last_seen_ms.store(now_millis(), Ordering::Relaxed);
        drop(bucket);
        self.maybe_activate_hot_cluster_defense(peer_ip, attack_type, count, score);
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
        let count = bucket.count.load(Ordering::Relaxed);
        let score = bucket.score.fetch_add(score_delta, Ordering::Relaxed) + score_delta;
        bucket.last_seen_ms.store(now_millis(), Ordering::Relaxed);
        drop(bucket);
        self.maybe_activate_hot_cluster_defense(peer_ip, attack_type, count, score);
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

    fn defense_action_effects(&self, limit: usize) -> Vec<ResourceSentinelDefenseActionEffect> {
        let mut items = self
            .defense_memory
            .iter()
            .map(|entry| {
                let bucket = entry.value();
                let effective_score = bucket.effective_score.load(Ordering::Relaxed);
                let ineffective_score = bucket.ineffective_score.load(Ordering::Relaxed);
                let total = effective_score.saturating_add(ineffective_score);
                ResourceSentinelDefenseActionEffect {
                    attack_type: entry.key().clone(),
                    preferred_action: bucket.preferred_action.clone(),
                    effective_score,
                    ineffective_score,
                    weak_score: bucket.weak_score.load(Ordering::Relaxed),
                    harmful_score: bucket.harmful_score.load(Ordering::Relaxed),
                    confidence: confidence_percent(effective_score, total),
                    last_outcome: defense_outcome_label(
                        bucket.last_outcome.load(Ordering::Relaxed),
                    )
                    .to_string(),
                    last_rejection_delta: bucket.last_rejection_delta.load(Ordering::Relaxed),
                    last_score_delta: bucket.last_score_delta.load(Ordering::Relaxed),
                    last_seen_ms: bucket.last_seen_ms.load(Ordering::Relaxed),
                }
            })
            .collect::<Vec<_>>();
        items.sort_by(|left, right| {
            right
                .harmful_score
                .cmp(&left.harmful_score)
                .then_with(|| right.effective_score.cmp(&left.effective_score))
                .then_with(|| right.ineffective_score.cmp(&left.ineffective_score))
                .then_with(|| right.last_seen_ms.cmp(&left.last_seen_ms))
        });
        items.truncate(limit);
        items
    }

    fn defense_decision_traces(&self, limit: usize) -> Vec<ResourceSentinelDefenseDecisionTrace> {
        let mut items = self
            .defense_decisions
            .iter()
            .map(|entry| {
                let bucket = entry.value();
                ResourceSentinelDefenseDecisionTrace {
                    attack_type: bucket.attack_type.clone(),
                    selected_action: bucket.selected_action.clone(),
                    default_action: bucket.default_action.clone(),
                    reason: bucket.reason.clone(),
                    mode: bucket.mode.clone(),
                    memory_outcome: bucket.memory_outcome.clone(),
                    confidence: bucket.confidence.load(Ordering::Relaxed),
                    effective_score: bucket.effective_score.load(Ordering::Relaxed),
                    ineffective_score: bucket.ineffective_score.load(Ordering::Relaxed),
                    weak_score: bucket.weak_score.load(Ordering::Relaxed),
                    harmful_score: bucket.harmful_score.load(Ordering::Relaxed),
                    used_memory: bucket.used_memory,
                    switched_action: bucket.switched_action,
                    observed_at_ms: bucket.observed_at_ms.load(Ordering::Relaxed),
                }
            })
            .collect::<Vec<_>>();
        items.sort_by(|left, right| right.observed_at_ms.cmp(&left.observed_at_ms));
        items.truncate(limit);
        items
    }

    fn active_cooldown_reason(&self, peer_ip: IpAddr, transport: &str) -> Option<String> {
        let now = now_millis();
        for key in cooldown_keys(peer_ip, transport) {
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
        let ip_activated = self.set_cooldown(
            format!("ip:{peer_ip}"),
            now + IP_COOLDOWN_MS,
            reason,
            reason,
            "ip_cluster_cooldown",
        );
        let cluster_activated = self.set_cooldown(
            format!("cluster:{}", cluster_key(peer_ip)),
            now + CLUSTER_COOLDOWN_MS,
            reason,
            reason,
            "ip_cluster_cooldown",
        );
        if ip_activated || cluster_activated {
            self.automated_defense_actions
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    fn maybe_activate_hot_cluster_defense(
        &self,
        peer_ip: IpAddr,
        attack_type: &str,
        count: u64,
        score: u64,
    ) {
        if !cluster_defense_allowed(attack_type, self.mode.load(Ordering::Relaxed), count, score) {
            return;
        }
        let hot_by_score =
            count >= HOT_CLUSTER_DEFENSE_MIN_COUNT && score >= HOT_CLUSTER_DEFENSE_SCORE;
        let hot_by_count = count >= HOT_CLUSTER_DEFENSE_COUNT;
        if !hot_by_score && !hot_by_count {
            return;
        }

        let mode = self.mode.load(Ordering::Relaxed);
        let Some(plan) = self.defense_plan(peer_ip, attack_type, mode) else {
            return;
        };
        let activated = self.set_cooldown(
            plan.key,
            now_millis() + plan.cooldown_ms,
            plan.reason,
            attack_type,
            plan.action,
        );
        if activated {
            self.automated_defense_actions
                .fetch_add(1, Ordering::Relaxed);
            self.note_signal(6);
        }
    }

    fn defense_plan(
        &self,
        peer_ip: IpAddr,
        attack_type: &str,
        mode: u8,
    ) -> Option<DefenseActionPlan> {
        let memory = self.defense_action_memory(attack_type);
        let selection = select_defense_action(attack_type, mode, memory.as_ref());
        self.record_defense_decision(attack_type, mode, &selection, memory.as_ref());
        let action = selection.action?;
        let plan = match action {
            DEFENSE_ACTION_TLS_PRE_ADMISSION => Some(tls_cluster_plan(peer_ip, attack_type, mode)),
            DEFENSE_ACTION_CLUSTER_CONNECTION => {
                Some(cluster_connection_plan(peer_ip, attack_type, mode))
            }
            _ => None,
        };
        if memory.is_some() && plan.is_some() {
            self.automated_defense_memory_hits
                .fetch_add(1, Ordering::Relaxed);
        }
        plan
    }

    fn record_defense_decision(
        &self,
        attack_type: &str,
        mode: u8,
        selection: &DefenseActionSelection,
        memory: Option<&DefenseActionMemorySnapshot>,
    ) {
        let now = now_millis();
        let (effective, ineffective, weak, harmful, outcome, confidence) = memory
            .map(|memory| {
                let total = memory
                    .effective_score
                    .saturating_add(memory.ineffective_score);
                (
                    memory.effective_score,
                    memory.ineffective_score,
                    memory.weak_score,
                    memory.harmful_score,
                    defense_outcome_label(memory.last_outcome).to_string(),
                    confidence_percent(memory.effective_score, total),
                )
            })
            .unwrap_or((0, 0, 0, 0, "none".to_string(), 0));
        self.defense_decisions.insert(
            attack_type.to_string(),
            DefenseDecisionBucket {
                attack_type: attack_type.to_string(),
                selected_action: selection.action.unwrap_or("none").to_string(),
                default_action: selection.default_action.unwrap_or("none").to_string(),
                reason: selection.reason.to_string(),
                mode: mode_label(mode).to_string(),
                memory_outcome: outcome,
                confidence: AtomicU64::new(confidence),
                effective_score: AtomicU64::new(effective),
                ineffective_score: AtomicU64::new(ineffective),
                weak_score: AtomicU64::new(weak),
                harmful_score: AtomicU64::new(harmful),
                used_memory: selection.used_memory,
                switched_action: selection.switched_action,
                observed_at_ms: AtomicU64::new(now),
            },
        );
    }

    fn defense_action_memory(&self, attack_type: &str) -> Option<DefenseActionMemorySnapshot> {
        self.defense_memory
            .get(attack_type)
            .map(|bucket| DefenseActionMemorySnapshot {
                preferred_action: bucket.preferred_action.clone(),
                effective_score: bucket.effective_score.load(Ordering::Relaxed),
                ineffective_score: bucket.ineffective_score.load(Ordering::Relaxed),
                weak_score: bucket.weak_score.load(Ordering::Relaxed),
                harmful_score: bucket.harmful_score.load(Ordering::Relaxed),
                last_outcome: bucket.last_outcome.load(Ordering::Relaxed),
            })
    }

    fn set_cooldown(
        &self,
        key: String,
        until_ms: u64,
        reason: &'static str,
        attack_type: &str,
        action: &'static str,
    ) -> bool {
        let now = now_millis();
        let previous = self
            .cooldowns
            .get(&key)
            .map(|bucket| bucket.until_ms.load(Ordering::Relaxed))
            .unwrap_or(0);
        if until_ms <= previous {
            return false;
        }
        let bucket = self.cooldowns.entry(key).or_insert_with(|| CooldownBucket {
            until_ms: AtomicU64::new(until_ms),
            created_ms: now,
            last_evaluated_ms: AtomicU64::new(now),
            last_rejections: AtomicU64::new(self.pre_admission_rejections.load(Ordering::Relaxed)),
            last_attack_score: AtomicU64::new(self.attack_score.load(Ordering::Relaxed)),
            extensions: AtomicU64::new(0),
            relaxations: AtomicU64::new(0),
            attack_type: attack_type.to_string(),
            action: action.to_string(),
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
        true
    }

    fn evaluate_defense_effects(&self, now: u64) {
        let current_rejections = self.pre_admission_rejections.load(Ordering::Relaxed);
        let current_score = self.attack_score.load(Ordering::Relaxed);
        for entry in self.cooldowns.iter() {
            let bucket = entry.value();
            let until = bucket.until_ms.load(Ordering::Relaxed);
            if until <= now {
                continue;
            }

            let last_eval = bucket.last_evaluated_ms.load(Ordering::Relaxed);
            if now.saturating_sub(last_eval) < DEFENSE_EFFECT_EVAL_INTERVAL_MS {
                continue;
            }
            if bucket
                .last_evaluated_ms
                .compare_exchange(last_eval, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_err()
            {
                continue;
            }

            let previous_rejections = bucket
                .last_rejections
                .swap(current_rejections, Ordering::Relaxed);
            let previous_score = bucket
                .last_attack_score
                .swap(current_score, Ordering::Relaxed);
            let rejection_delta = current_rejections.saturating_sub(previous_rejections);
            if rejection_delta >= DEFENSE_EFFECT_REJECTION_DELTA
                && current_score >= SCORE_UNDER_ATTACK
            {
                self.extend_effective_cooldown(
                    bucket,
                    now,
                    until,
                    current_score,
                    rejection_delta,
                    previous_score,
                );
            } else if rejection_delta == 0 && current_score < SCORE_ELEVATED {
                self.relax_quiet_cooldown(bucket, now, until);
            } else {
                self.score_observed_cooldown(
                    bucket,
                    rejection_delta,
                    previous_score,
                    current_score,
                );
            }
        }
    }

    fn extend_effective_cooldown(
        &self,
        bucket: &CooldownBucket,
        now: u64,
        observed_until: u64,
        current_score: u64,
        rejection_delta: u64,
        previous_score: u64,
    ) {
        let extension = if current_score >= SCORE_SURVIVAL {
            DEFENSE_EFFECT_SURVIVAL_EXTEND_MS
        } else {
            DEFENSE_EFFECT_EXTEND_MS
        };
        let max_until = bucket
            .created_ms
            .saturating_add(DEFENSE_EFFECT_MAX_LIFETIME_MS);
        let target_until = observed_until.saturating_add(extension).min(max_until);
        if target_until <= observed_until || target_until <= now {
            return;
        }
        if bucket
            .until_ms
            .compare_exchange(
                observed_until,
                target_until,
                Ordering::Relaxed,
                Ordering::Relaxed,
            )
            .is_ok()
        {
            bucket.extensions.fetch_add(1, Ordering::Relaxed);
            self.automated_defense_extensions
                .fetch_add(1, Ordering::Relaxed);
            self.note_defense_effect(
                &bucket.attack_type,
                &bucket.action,
                DEFENSE_OUTCOME_EFFECTIVE,
                rejection_delta,
                current_score as i64 - previous_score as i64,
            );
        }
    }

    fn score_observed_cooldown(
        &self,
        bucket: &CooldownBucket,
        rejection_delta: u64,
        previous_score: u64,
        current_score: u64,
    ) {
        if current_score < SCORE_ELEVATED {
            return;
        }
        let score_delta = current_score as i64 - previous_score as i64;
        let outcome = if current_score >= SCORE_UNDER_ATTACK
            && rejection_delta == 0
            && score_delta >= SCORE_ELEVATED as i64
        {
            DEFENSE_OUTCOME_HARMFUL
        } else if current_score >= SCORE_UNDER_ATTACK
            && rejection_delta < DEFENSE_EFFECT_REJECTION_DELTA
        {
            DEFENSE_OUTCOME_WEAK
        } else {
            DEFENSE_OUTCOME_UNKNOWN
        };
        if outcome != DEFENSE_OUTCOME_UNKNOWN {
            self.note_defense_effect(
                &bucket.attack_type,
                &bucket.action,
                outcome,
                rejection_delta,
                score_delta,
            );
        }
    }

    fn relax_quiet_cooldown(&self, bucket: &CooldownBucket, now: u64, observed_until: u64) {
        let target_until = now.saturating_add(DEFENSE_EFFECT_RELAX_TO_MS);
        if target_until >= observed_until {
            return;
        }
        if bucket
            .until_ms
            .compare_exchange(
                observed_until,
                target_until,
                Ordering::Relaxed,
                Ordering::Relaxed,
            )
            .is_ok()
        {
            bucket.relaxations.fetch_add(1, Ordering::Relaxed);
            self.automated_defense_relaxations
                .fetch_add(1, Ordering::Relaxed);
            self.note_defense_effect(
                &bucket.attack_type,
                &bucket.action,
                DEFENSE_OUTCOME_RECOVERED,
                0,
                0,
            );
        }
    }

    fn note_defense_effect(
        &self,
        attack_type: &str,
        action: &str,
        outcome: u8,
        rejection_delta: u64,
        score_delta: i64,
    ) {
        let now = now_millis();
        let mut bucket = self
            .defense_memory
            .entry(attack_type.to_string())
            .or_insert_with(|| DefenseMemoryBucket {
                preferred_action: action.to_string(),
                effective_score: AtomicU64::new(0),
                ineffective_score: AtomicU64::new(0),
                weak_score: AtomicU64::new(0),
                harmful_score: AtomicU64::new(0),
                last_outcome: AtomicU8::new(DEFENSE_OUTCOME_UNKNOWN),
                last_rejection_delta: AtomicU64::new(0),
                last_score_delta: AtomicI64::new(0),
                last_seen_ms: AtomicU64::new(now),
            });
        bucket.last_seen_ms.store(now, Ordering::Relaxed);
        bucket.last_outcome.store(outcome, Ordering::Relaxed);
        bucket
            .last_rejection_delta
            .store(rejection_delta, Ordering::Relaxed);
        bucket
            .last_score_delta
            .store(score_delta, Ordering::Relaxed);
        match outcome {
            DEFENSE_OUTCOME_EFFECTIVE => {
                bucket.effective_score.fetch_add(1, Ordering::Relaxed);
                bucket.preferred_action = action.to_string();
            }
            DEFENSE_OUTCOME_WEAK => {
                bucket.weak_score.fetch_add(1, Ordering::Relaxed);
                bucket.ineffective_score.fetch_add(1, Ordering::Relaxed);
            }
            DEFENSE_OUTCOME_HARMFUL => {
                bucket.harmful_score.fetch_add(1, Ordering::Relaxed);
                bucket.ineffective_score.fetch_add(1, Ordering::Relaxed);
            }
            DEFENSE_OUTCOME_RECOVERED => {}
            _ => {}
        }
    }

    fn maybe_attack_audit_event(&self) -> Option<SecurityEventRecord> {
        let snapshot = self.snapshot();
        let diagnosis = snapshot.attack_diagnosis.clone();
        if !should_emit_attack_audit(&diagnosis, &snapshot.attack_lifecycle) {
            return None;
        }

        let now = now_millis();
        let signature = attack_audit_signature(&diagnosis, &snapshot.attack_lifecycle);
        let last_signature = self.last_attack_audit_signature.load(Ordering::Relaxed);
        let required_interval = if signature == last_signature {
            ATTACK_AUDIT_REPEAT_COOLDOWN_MS
        } else {
            ATTACK_AUDIT_MIN_INTERVAL_MS
        };
        let last_audit = self.last_attack_audit_ms.load(Ordering::Relaxed);
        if now.saturating_sub(last_audit) < required_interval {
            return None;
        }
        if self
            .last_attack_audit_ms
            .compare_exchange(last_audit, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return None;
        }
        self.last_attack_audit_signature
            .store(signature, Ordering::Relaxed);
        self.automated_audit_events.fetch_add(1, Ordering::Relaxed);

        Some(build_attack_audit_event(snapshot))
    }

    fn update_attack_lifecycle(
        &self,
        diagnosis: &ResourceSentinelAttackDiagnosis,
    ) -> ResourceSentinelAttackLifecycle {
        let now = now_millis();
        let current = self.attack_phase.load(Ordering::Relaxed);
        let next = next_attack_phase(current, diagnosis);
        let transitioned = next != current
            && self
                .attack_phase
                .compare_exchange(current, next, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok();
        let previous = if transitioned { current } else { next };
        if transitioned {
            self.attack_phase_since_ms.store(now, Ordering::Relaxed);
            match next {
                ATTACK_PHASE_STARTED => self.start_attack_session(now),
                ATTACK_PHASE_ENDED => self.end_attack_session(now),
                _ => {}
            }
        }
        let phase_since_ms = now.saturating_sub(self.attack_phase_since_ms.load(Ordering::Relaxed));
        ResourceSentinelAttackLifecycle {
            phase: attack_phase_label(next).to_string(),
            previous_phase: attack_phase_label(previous).to_string(),
            phase_since_ms,
            transitioned,
        }
    }

    fn start_attack_session(&self, now: u64) {
        let next_id = self
            .attack_session_id
            .load(Ordering::Relaxed)
            .saturating_add(1);
        self.attack_session_id
            .store(next_id.max(1), Ordering::Relaxed);
        self.attack_session_started_ms.store(now, Ordering::Relaxed);
        self.attack_session_ended_ms.store(0, Ordering::Relaxed);
        self.attack_session_peak_score
            .store(self.attack_score.load(Ordering::Relaxed), Ordering::Relaxed);
        self.attack_session_start_rejections.store(
            self.pre_admission_rejections.load(Ordering::Relaxed),
            Ordering::Relaxed,
        );
        self.attack_session_start_aggregated_events.store(
            self.aggregated_events.load(Ordering::Relaxed),
            Ordering::Relaxed,
        );
        self.attack_session_start_defense_actions.store(
            self.automated_defense_actions.load(Ordering::Relaxed),
            Ordering::Relaxed,
        );
        self.attack_session_start_defense_extensions.store(
            self.automated_defense_extensions.load(Ordering::Relaxed),
            Ordering::Relaxed,
        );
        self.attack_session_start_defense_relaxations.store(
            self.automated_defense_relaxations.load(Ordering::Relaxed),
            Ordering::Relaxed,
        );
        self.attack_session_start_audit_events.store(
            self.automated_audit_events.load(Ordering::Relaxed),
            Ordering::Relaxed,
        );
    }

    fn end_attack_session(&self, now: u64) {
        if self.attack_session_started_ms.load(Ordering::Relaxed) > 0 {
            self.attack_session_ended_ms.store(now, Ordering::Relaxed);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn attack_session_snapshot(
        &self,
        attack_score: u64,
        pre_admission_rejections: u64,
        aggregated_events: u64,
        automated_defense_actions: u64,
        automated_defense_extensions: u64,
        automated_defense_relaxations: u64,
        automated_audit_events: u64,
        diagnosis: &ResourceSentinelAttackDiagnosis,
        lifecycle: &ResourceSentinelAttackLifecycle,
        top_attack_clusters: &[ResourceSentinelClusterSnapshot],
    ) -> ResourceSentinelAttackSession {
        let session_id = self.attack_session_id.load(Ordering::Relaxed);
        let started_at_ms = self.attack_session_started_ms.load(Ordering::Relaxed);
        let ended_raw = self.attack_session_ended_ms.load(Ordering::Relaxed);
        if session_id == 0 || started_at_ms == 0 {
            return ResourceSentinelAttackSession::default();
        }

        let mut peak_score = self.attack_session_peak_score.load(Ordering::Relaxed);
        while attack_score > peak_score {
            match self.attack_session_peak_score.compare_exchange_weak(
                peak_score,
                attack_score,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    peak_score = attack_score;
                    break;
                }
                Err(actual) => peak_score = actual,
            }
        }

        let now = now_millis();
        let ended_at_ms = (ended_raw > 0).then_some(ended_raw);
        let duration_end = ended_at_ms.unwrap_or(now);
        let duration_ms = duration_end.saturating_sub(started_at_ms);
        let defense_actions = automated_defense_actions.saturating_sub(
            self.attack_session_start_defense_actions
                .load(Ordering::Relaxed),
        );
        let defense_extensions = automated_defense_extensions.saturating_sub(
            self.attack_session_start_defense_extensions
                .load(Ordering::Relaxed),
        );
        let defense_relaxations = automated_defense_relaxations.saturating_sub(
            self.attack_session_start_defense_relaxations
                .load(Ordering::Relaxed),
        );
        let audit_event_count = automated_audit_events.saturating_sub(
            self.attack_session_start_audit_events
                .load(Ordering::Relaxed),
        );
        let session_rejections = pre_admission_rejections
            .saturating_sub(self.attack_session_start_rejections.load(Ordering::Relaxed));
        let session_aggregated_events = aggregated_events.saturating_sub(
            self.attack_session_start_aggregated_events
                .load(Ordering::Relaxed),
        );
        let final_outcome =
            session_outcome(lifecycle.phase.as_str(), diagnosis.active_defense.as_str());
        let top_clusters = top_attack_clusters
            .iter()
            .take(3)
            .cloned()
            .collect::<Vec<_>>();
        let primary_pressure = diagnosis.primary_pressure.clone();
        let peak_severity = severity_for_score(peak_score).to_string();
        let summary = build_attack_session_summary(
            session_id,
            duration_ms,
            peak_severity.as_str(),
            primary_pressure.as_str(),
            top_clusters.first(),
            defense_actions,
            defense_extensions,
            defense_relaxations,
            final_outcome,
        );

        ResourceSentinelAttackSession {
            session_id,
            phase: lifecycle.phase.clone(),
            started_at_ms,
            ended_at_ms,
            duration_ms,
            peak_severity,
            peak_attack_score: peak_score,
            primary_pressure,
            top_clusters,
            defense_actions,
            defense_extensions,
            defense_relaxations,
            audit_event_count,
            pre_admission_rejections: session_rejections,
            aggregated_events: session_aggregated_events,
            final_outcome: final_outcome.to_string(),
            summary,
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
        if let Some(audit_event) = self.resource_sentinel.maybe_attack_audit_event() {
            store.enqueue_security_event(audit_event);
            self.persist_resource_sentinel_state(store, true);
        } else {
            self.persist_resource_sentinel_state(store, false);
        }
    }

    fn persist_resource_sentinel_state(&self, store: &SqliteStore, force: bool) {
        let Some(snapshot) = self.resource_sentinel.maybe_persistence_snapshot(force) else {
            return;
        };
        let memory = self.resource_sentinel.defense_memory_exports();
        let store = store.clone();
        tokio::spawn(async move {
            if let Err(err) = store
                .upsert_resource_sentinel_attack_session(&snapshot)
                .await
            {
                log::warn!(
                    "Failed to persist resource sentinel attack session: {}",
                    err
                );
            }
            for record in memory {
                if let Err(err) = store.upsert_resource_sentinel_defense_memory(&record).await {
                    log::warn!(
                        "Failed to persist resource sentinel defense memory for {}: {}",
                        record.attack_type,
                        err
                    );
                }
            }
        });
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

#[derive(Debug, Clone)]
struct DefenseActionPlan {
    key: String,
    action: &'static str,
    reason: &'static str,
    cooldown_ms: u64,
}

fn debt_keys(peer_ip: IpAddr) -> [String; 2] {
    [
        format!("ip:{peer_ip}"),
        format!("cluster:{}", cluster_key(peer_ip)),
    ]
}

fn cooldown_keys(peer_ip: IpAddr, transport: &str) -> [String; 3] {
    [
        format!("ip:{peer_ip}"),
        format!("cluster:{}", cluster_key(peer_ip)),
        format!("transport:{}:cluster:{}", transport, cluster_key(peer_ip)),
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

fn pressure_level_code(level: &str) -> u8 {
    match level {
        "attack" => 3,
        "high" => 2,
        "elevated" => 1,
        _ => 0,
    }
}

fn pressure_level_label(level: u8) -> &'static str {
    match level {
        3 => "attack",
        2 => "high",
        1 => "elevated",
        _ => "normal",
    }
}

fn attack_phase_label(phase: u8) -> &'static str {
    match phase {
        ATTACK_PHASE_STARTED => "started",
        ATTACK_PHASE_SUSTAINED => "sustained",
        ATTACK_PHASE_MITIGATING => "mitigating",
        ATTACK_PHASE_ENDED => "ended",
        _ => "normal",
    }
}

fn defense_outcome_label(outcome: u8) -> &'static str {
    match outcome {
        DEFENSE_OUTCOME_EFFECTIVE => "effective",
        DEFENSE_OUTCOME_WEAK => "weak",
        DEFENSE_OUTCOME_HARMFUL => "harmful",
        DEFENSE_OUTCOME_RECOVERED => "recovered",
        _ => "unknown",
    }
}

fn defense_outcome_code(outcome: &str) -> u8 {
    match outcome {
        "effective" => DEFENSE_OUTCOME_EFFECTIVE,
        "weak" => DEFENSE_OUTCOME_WEAK,
        "harmful" => DEFENSE_OUTCOME_HARMFUL,
        "recovered" => DEFENSE_OUTCOME_RECOVERED,
        _ => DEFENSE_OUTCOME_UNKNOWN,
    }
}

fn confidence_percent(effective_score: u64, total_score: u64) -> u64 {
    if total_score == 0 {
        0
    } else {
        effective_score.saturating_mul(100) / total_score
    }
}

fn severity_for_score(score: u64) -> &'static str {
    if score >= SCORE_SURVIVAL {
        "critical"
    } else if score >= SCORE_UNDER_ATTACK {
        "high"
    } else if score >= SCORE_ELEVATED {
        "elevated"
    } else {
        "normal"
    }
}

fn session_outcome(phase: &str, active_defense: &str) -> &'static str {
    match phase {
        "ended" => "recovered",
        "mitigating" => "mitigating",
        "started" | "sustained" if active_defense == "defense_effective_extending" => {
            "defense_effective"
        }
        "started" | "sustained" => "active",
        _ => "idle",
    }
}

fn next_attack_phase(current: u8, diagnosis: &ResourceSentinelAttackDiagnosis) -> u8 {
    match diagnosis.severity.as_str() {
        "critical" | "high" => {
            if matches!(current, ATTACK_PHASE_NORMAL | ATTACK_PHASE_ENDED) {
                ATTACK_PHASE_STARTED
            } else {
                ATTACK_PHASE_SUSTAINED
            }
        }
        "elevated" | "watch" => {
            if matches!(current, ATTACK_PHASE_STARTED | ATTACK_PHASE_SUSTAINED) {
                ATTACK_PHASE_MITIGATING
            } else {
                current
            }
        }
        _ => {
            if matches!(
                current,
                ATTACK_PHASE_STARTED | ATTACK_PHASE_SUSTAINED | ATTACK_PHASE_MITIGATING
            ) {
                ATTACK_PHASE_ENDED
            } else {
                ATTACK_PHASE_NORMAL
            }
        }
    }
}

fn build_attack_session_summary(
    session_id: u64,
    duration_ms: u64,
    peak_severity: &str,
    primary_pressure: &str,
    top_cluster: Option<&ResourceSentinelClusterSnapshot>,
    defense_actions: u64,
    defense_extensions: u64,
    defense_relaxations: u64,
    final_outcome: &str,
) -> String {
    let cluster_text = top_cluster
        .map(|cluster| {
            format!(
                "最热簇 {}，类型 {}，样本 IP {}。",
                cluster.cluster, cluster.attack_type, cluster.sample_ip
            )
        })
        .unwrap_or_else(|| "未形成稳定最热簇。".to_string());
    format!(
        "攻击会话 #{session_id} 持续 {duration_ms}ms，峰值等级 {peak_severity}，主压力 {primary_pressure}。{cluster_text}自动防御动作 {defense_actions} 次，延长 {defense_extensions} 次，收缩 {defense_relaxations} 次，当前结果 {final_outcome}。"
    )
}

fn build_ingress_gap_analysis(
    pre_admission_rejections: u64,
    aggregated_events: u64,
    top_attack_clusters: &[ResourceSentinelClusterSnapshot],
    storage_queue_usage_percent: u64,
) -> ResourceSentinelIngressGapAnalysis {
    let rust_observed_intercepts = pre_admission_rejections.saturating_add(aggregated_events);
    let tls_or_idle_pressure = top_attack_clusters.iter().any(|cluster| {
        matches!(
            cluster.attack_type.as_str(),
            "slow_tls_handshake" | "tls_handshake_failure" | "idle_no_request"
        )
    });
    let likely_absorption_layer = if tls_or_idle_pressure && rust_observed_intercepts > 0 {
        "transport_or_cdn_edge"
    } else if aggregated_events > pre_admission_rejections {
        "rust_event_aggregation"
    } else if pre_admission_rejections > 0 {
        "rust_pre_admission"
    } else {
        "unknown"
    };
    let confidence = if rust_observed_intercepts == 0 {
        "low"
    } else if storage_queue_usage_percent >= FAST_PATH_STORAGE_QUEUE_PERCENT || tls_or_idle_pressure
    {
        "medium"
    } else {
        "watch"
    };
    let summary = match likely_absorption_layer {
        "transport_or_cdn_edge" => {
            "Rust 侧观测以传输层/连接型压力为主，CDN 计数可能显著高于本进程完整事件记录。"
        }
        "rust_event_aggregation" => "Rust 侧已大量聚合低价值事件，本地明细记录会低于真实到达压力。",
        "rust_pre_admission" => "Rust 侧前置 admission 正在吸收压力，后端完整 L7 记录会相对较低。",
        _ => "当前 Rust 侧证据不足，暂时无法可靠判断 CDN 与本进程计数差异来源。",
    }
    .to_string();

    ResourceSentinelIngressGapAnalysis {
        cdn_observed_requests: None,
        rust_observed_intercepts,
        estimated_outer_layer_absorption_ratio: None,
        likely_absorption_layer: likely_absorption_layer.to_string(),
        confidence: confidence.to_string(),
        summary,
    }
}

fn build_resource_pressure_feedback(
    pressure_level: u8,
    storage_queue_usage_percent: u64,
    fast_path_activations: u64,
    attack_score: u64,
) -> ResourceSentinelResourcePressureFeedback {
    let pressure_label = pressure_level_label(pressure_level);
    let resource_outcome = if fast_path_activations > 0 {
        "fast_path_guard_active"
    } else if storage_queue_usage_percent >= FAST_PATH_STORAGE_QUEUE_PERCENT {
        "storage_survival_pressure"
    } else if attack_score >= SCORE_SURVIVAL {
        "attack_survival_pressure"
    } else if attack_score >= SCORE_UNDER_ATTACK || matches!(pressure_label, "high" | "attack") {
        "resource_under_attack"
    } else {
        "resource_monitoring"
    };
    let scoring_hint = match resource_outcome {
        "fast_path_guard_active" => "prefer_highest_confidence_or_survival_action",
        "storage_survival_pressure" => "prioritize_event_aggregation_and_low_value_write_trim",
        "attack_survival_pressure" => "prioritize_pre_admission_and_cluster_budget",
        "resource_under_attack" => "continue_effect_scoring",
        _ => "observe",
    };
    let summary = format!(
        "资源压力 {pressure_label}，SQLite 队列 {storage_queue_usage_percent}%，fast path 触发 {fast_path_activations} 次，评分提示 {scoring_hint}。"
    );

    ResourceSentinelResourcePressureFeedback {
        pressure_level: pressure_label.to_string(),
        storage_queue_usage_percent,
        fast_path_activations,
        resource_outcome: resource_outcome.to_string(),
        scoring_hint: scoring_hint.to_string(),
        summary,
    }
}

fn build_attack_migrations(
    attack_score: u64,
    top_attack_clusters: &[ResourceSentinelClusterSnapshot],
    now: u64,
) -> Vec<ResourceSentinelAttackMigration> {
    if attack_score < SCORE_UNDER_ATTACK || top_attack_clusters.len() < 2 {
        return Vec::new();
    }
    let first = &top_attack_clusters[0];
    let second = &top_attack_clusters[1];
    if first.cluster == second.cluster && first.attack_type == second.attack_type {
        return Vec::new();
    }
    let score_gap = first.score.saturating_sub(second.score);
    if second.score == 0 || score_gap > first.score / 2 {
        return Vec::new();
    }
    vec![ResourceSentinelAttackMigration {
        from_cluster: second.cluster.clone(),
        to_cluster: first.cluster.clone(),
        from_attack_type: second.attack_type.clone(),
        to_attack_type: first.attack_type.clone(),
        detected_at_ms: now,
        reason: "top_attack_cluster_shift_with_continuous_pressure".to_string(),
        confidence: "medium".to_string(),
    }]
}

fn build_attack_report_preview(
    session: &ResourceSentinelAttackSession,
    effects: &[ResourceSentinelDefenseActionEffect],
    decisions: &[ResourceSentinelDefenseDecisionTrace],
    ingress_gap: &ResourceSentinelIngressGapAnalysis,
    pressure: &ResourceSentinelResourcePressureFeedback,
    migrations: &[ResourceSentinelAttackMigration],
) -> Option<ResourceSentinelAttackReport> {
    if session.session_id == 0 {
        return None;
    }
    let what_worked = effects
        .iter()
        .filter(|effect| effect.effective_score > effect.ineffective_score)
        .map(|effect| {
            format!(
                "{} 使用 {} 置信度 {}%",
                effect.attack_type, effect.preferred_action, effect.confidence
            )
        })
        .collect::<Vec<_>>();
    let what_was_weak = effects
        .iter()
        .filter(|effect| effect.weak_score > 0)
        .map(|effect| format!("{} 最近存在 weak 评分", effect.attack_type))
        .collect::<Vec<_>>();
    let what_was_harmful = effects
        .iter()
        .filter(|effect| effect.harmful_score > 0)
        .map(|effect| format!("{} 最近存在 harmful 评分", effect.attack_type))
        .collect::<Vec<_>>();
    let mut recommendations = Vec::new();
    if decisions.iter().any(|decision| decision.switched_action) {
        recommendations
            .push("继续保留基于效果评分的动作切换，避免重复使用弱/有害动作。".to_string());
    }
    if pressure.fast_path_activations > 0 {
        recommendations
            .push("保留 fast path 快速保护，优先保护 admission、聚合与存储队列。".to_string());
    }
    if !migrations.is_empty() {
        recommendations.push("攻击簇存在迁移迹象，后续策略应按会话连续性处理新簇。".to_string());
    }
    if recommendations.is_empty() {
        recommendations.push("继续观察当前自动化策略效果评分。".to_string());
    }

    Some(ResourceSentinelAttackReport {
        session_id: session.session_id,
        generated_at_ms: now_millis(),
        summary: format!(
            "攻击会话 #{} 当前阶段 {}，峰值 {}，结果 {}。",
            session.session_id, session.phase, session.peak_severity, session.final_outcome
        ),
        what_worked,
        what_was_weak,
        what_was_harmful,
        cdn_rust_gap_analysis: ingress_gap.summary.clone(),
        resource_pressure_summary: pressure.summary.clone(),
        recommendations,
    })
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

fn cluster_defense_allowed(attack_type: &str, mode: u8, count: u64, score: u64) -> bool {
    match attack_type {
        "slow_tls_handshake"
        | "idle_no_request"
        | "l4_admission_reject"
        | "tls_handshake_failure" => true,
        "provider_intercept" | "l7_security_event" | "l4_security_event" => {
            mode >= MODE_UNDER_ATTACK
                && count >= HOT_CLUSTER_DEFENSE_COUNT
                && score >= HOT_CLUSTER_DEFENSE_SCORE.saturating_mul(2)
        }
        _ => false,
    }
}

fn select_defense_action(
    attack_type: &str,
    mode: u8,
    memory: Option<&DefenseActionMemorySnapshot>,
) -> DefenseActionSelection {
    let default_action = default_defense_action(attack_type);
    let Some(default_action) = default_action else {
        return DefenseActionSelection {
            action: None,
            default_action: None,
            reason: "unsupported_attack_type",
            used_memory: memory.is_some(),
            switched_action: false,
        };
    };
    let Some(memory) = memory else {
        return DefenseActionSelection {
            action: Some(default_action),
            default_action: Some(default_action),
            reason: "default_without_memory",
            used_memory: false,
            switched_action: false,
        };
    };

    if action_looks_harmful(memory) {
        let alternative = alternative_defense_action(attack_type, default_action);
        return DefenseActionSelection {
            action: alternative,
            default_action: Some(default_action),
            reason: if alternative.is_some() {
                "harmful_memory_switched"
            } else {
                "harmful_memory_no_safe_alternative"
            },
            used_memory: true,
            switched_action: alternative.is_some_and(|action| action != default_action),
        };
    }

    if action_looks_weak(memory) && mode >= MODE_SURVIVAL {
        let alternative = alternative_defense_action(attack_type, default_action);
        let action = alternative.unwrap_or(default_action);
        return DefenseActionSelection {
            action: Some(action),
            default_action: Some(default_action),
            reason: if alternative.is_some() {
                "weak_memory_survival_switched"
            } else {
                "weak_memory_survival_default"
            },
            used_memory: true,
            switched_action: action != default_action,
        };
    }

    if memory.effective_score > memory.ineffective_score
        && is_compatible_defense_action(attack_type, memory.preferred_action.as_str())
    {
        let action = canonical_defense_action(memory.preferred_action.as_str());
        return DefenseActionSelection {
            action: Some(action),
            default_action: Some(default_action),
            reason: "effective_memory_reused",
            used_memory: true,
            switched_action: action != default_action,
        };
    }

    DefenseActionSelection {
        action: Some(default_action),
        default_action: Some(default_action),
        reason: "memory_insufficient_default",
        used_memory: true,
        switched_action: false,
    }
}

fn default_defense_action(attack_type: &str) -> Option<&'static str> {
    match attack_type {
        "slow_tls_handshake" | "tls_handshake_failure" => Some(DEFENSE_ACTION_TLS_PRE_ADMISSION),
        "idle_no_request" | "l4_admission_reject" => Some(DEFENSE_ACTION_CLUSTER_CONNECTION),
        "provider_intercept" | "l7_security_event" | "l4_security_event" => None,
        _ => None,
    }
}

fn alternative_defense_action(attack_type: &str, current: &str) -> Option<&'static str> {
    match (attack_type, current) {
        ("slow_tls_handshake" | "tls_handshake_failure", DEFENSE_ACTION_TLS_PRE_ADMISSION) => {
            Some(DEFENSE_ACTION_CLUSTER_CONNECTION)
        }
        ("slow_tls_handshake" | "tls_handshake_failure", DEFENSE_ACTION_CLUSTER_CONNECTION) => {
            Some(DEFENSE_ACTION_TLS_PRE_ADMISSION)
        }
        _ => None,
    }
}

fn action_looks_harmful(memory: &DefenseActionMemorySnapshot) -> bool {
    memory.last_outcome == DEFENSE_OUTCOME_HARMFUL
        || memory.harmful_score > memory.effective_score.max(1)
}

fn action_looks_weak(memory: &DefenseActionMemorySnapshot) -> bool {
    memory.weak_score > 0 && memory.effective_score <= memory.ineffective_score
}

fn is_compatible_defense_action(attack_type: &str, action: &str) -> bool {
    match action {
        DEFENSE_ACTION_TLS_PRE_ADMISSION => {
            matches!(attack_type, "slow_tls_handshake" | "tls_handshake_failure")
        }
        DEFENSE_ACTION_CLUSTER_CONNECTION => matches!(
            attack_type,
            "slow_tls_handshake"
                | "tls_handshake_failure"
                | "idle_no_request"
                | "l4_admission_reject"
        ),
        _ => false,
    }
}

fn canonical_defense_action(action: &str) -> &'static str {
    match action {
        DEFENSE_ACTION_TLS_PRE_ADMISSION => DEFENSE_ACTION_TLS_PRE_ADMISSION,
        DEFENSE_ACTION_CLUSTER_CONNECTION => DEFENSE_ACTION_CLUSTER_CONNECTION,
        _ => DEFENSE_ACTION_CLUSTER_CONNECTION,
    }
}

fn hot_cluster_cooldown_reason(attack_type: &str) -> &'static str {
    match attack_type {
        "slow_tls_handshake" => "hot_slow_tls_cluster",
        "idle_no_request" => "hot_idle_no_request_cluster",
        "l4_admission_reject" => "hot_l4_admission_cluster",
        "tls_handshake_failure" => "hot_tls_failure_cluster",
        "provider_intercept" => "hot_provider_intercept_cluster",
        "l7_security_event" => "hot_l7_security_cluster",
        "l4_security_event" => "hot_l4_security_cluster",
        _ => "hot_attack_cluster",
    }
}

fn tls_cluster_plan(peer_ip: IpAddr, attack_type: &str, mode: u8) -> DefenseActionPlan {
    DefenseActionPlan {
        key: format!("transport:tls:cluster:{}", cluster_key(peer_ip)),
        action: "tls_pre_admission_cooldown",
        reason: hot_cluster_cooldown_reason(attack_type),
        cooldown_ms: hot_cluster_cooldown_ms(mode),
    }
}

fn cluster_connection_plan(peer_ip: IpAddr, attack_type: &str, mode: u8) -> DefenseActionPlan {
    DefenseActionPlan {
        key: format!("cluster:{}", cluster_key(peer_ip)),
        action: "cluster_connection_cooldown",
        reason: hot_cluster_cooldown_reason(attack_type),
        cooldown_ms: hot_cluster_cooldown_ms(mode),
    }
}

fn hot_cluster_cooldown_ms(mode: u8) -> u64 {
    if mode >= MODE_SURVIVAL {
        SURVIVAL_CLUSTER_DEFENSE_COOLDOWN_MS
    } else {
        HOT_CLUSTER_DEFENSE_COOLDOWN_MS
    }
}

#[allow(clippy::too_many_arguments)]
fn build_attack_diagnosis(
    mode: &str,
    attack_score: u64,
    active_cooldowns: u64,
    pre_admission_rejections: u64,
    aggregated_events: u64,
    automated_defense_actions: u64,
    automated_defense_extensions: u64,
    automated_defense_relaxations: u64,
    automated_defense_memory_hits: u64,
    top_attack_clusters: &[ResourceSentinelClusterSnapshot],
    defense_action_effects: &[ResourceSentinelDefenseActionEffect],
    defense_decision_traces: &[ResourceSentinelDefenseDecisionTrace],
) -> ResourceSentinelAttackDiagnosis {
    let top_cluster = top_attack_clusters.first().cloned();
    let severity = if matches!(mode, "survival") || attack_score >= SCORE_SURVIVAL {
        "critical"
    } else if matches!(mode, "under_attack") || attack_score >= SCORE_UNDER_ATTACK {
        "high"
    } else if matches!(mode, "elevated") || attack_score >= SCORE_ELEVATED {
        "elevated"
    } else if top_cluster.is_some() {
        "watch"
    } else {
        "normal"
    };
    let primary_pressure = top_cluster
        .as_ref()
        .map(|cluster| pressure_label_for_attack_type(&cluster.attack_type))
        .unwrap_or("none")
        .to_string();
    let active_defense = if automated_defense_extensions > 0 {
        "defense_effective_extending"
    } else if automated_defense_relaxations > 0 && !matches!(severity, "high" | "critical") {
        "defense_relaxing"
    } else if active_cooldowns > 0 {
        "cooldown_active"
    } else if automated_defense_actions > 0 {
        "defense_recently_active"
    } else if aggregated_events > 0 {
        "event_aggregation_active"
    } else {
        "monitoring"
    }
    .to_string();
    let recommended_next_action = recommended_action_for_diagnosis(
        severity,
        primary_pressure.as_str(),
        active_defense.as_str(),
    )
    .to_string();

    let mut evidence = Vec::new();
    evidence.push(format!("mode={mode} attack_score={attack_score}"));
    if let Some(cluster) = top_cluster.as_ref() {
        evidence.push(format!(
            "top_cluster={} attack_type={} transport={} reason={} count={} score={} sample_ip={}",
            cluster.cluster,
            cluster.attack_type,
            cluster.transport,
            cluster.reason,
            cluster.count,
            cluster.score,
            cluster.sample_ip
        ));
    }
    if pre_admission_rejections > 0 {
        evidence.push(format!(
            "pre_admission_rejections={pre_admission_rejections}"
        ));
    }
    if active_cooldowns > 0 || automated_defense_actions > 0 {
        evidence.push(format!(
            "active_cooldowns={active_cooldowns} automated_actions={automated_defense_actions} extensions={automated_defense_extensions} relaxations={automated_defense_relaxations} memory_hits={automated_defense_memory_hits}"
        ));
    }
    if aggregated_events > 0 {
        evidence.push(format!("aggregated_events={aggregated_events}"));
    }
    if let Some(effect) = defense_action_effects.first() {
        evidence.push(format!(
            "defense_effect attack_type={} action={} outcome={} confidence={} effective={} weak={} harmful={}",
            effect.attack_type,
            effect.preferred_action,
            effect.last_outcome,
            effect.confidence,
            effect.effective_score,
            effect.weak_score,
            effect.harmful_score
        ));
    }
    if let Some(trace) = defense_decision_traces.first() {
        evidence.push(format!(
            "defense_decision attack_type={} selected_action={} reason={} mode={} switched={} confidence={}",
            trace.attack_type,
            trace.selected_action,
            trace.reason,
            trace.mode,
            trace.switched_action,
            trace.confidence
        ));
    }

    let summary = build_attack_summary(
        severity,
        primary_pressure.as_str(),
        active_defense.as_str(),
        top_cluster.as_ref(),
    );

    ResourceSentinelAttackDiagnosis {
        severity: severity.to_string(),
        primary_pressure,
        summary,
        active_defense,
        recommended_next_action,
        evidence,
        top_cluster,
    }
}

fn pressure_label_for_attack_type(attack_type: &str) -> &'static str {
    match attack_type {
        "slow_tls_handshake" | "tls_handshake_failure" => "tls_handshake_resource",
        "idle_no_request" => "idle_connection_resource",
        "l4_admission_reject" | "pre_admission_reject" | "cooldown_reject" => {
            "connection_admission"
        }
        "provider_intercept" => "upstream_provider_intercept",
        "l7_security_event" => "l7_policy_pressure",
        "l4_security_event" => "l4_policy_pressure",
        "event_aggregation" => "event_persistence",
        _ => "mixed_resource_pressure",
    }
}

fn recommended_action_for_diagnosis(
    severity: &str,
    primary_pressure: &str,
    active_defense: &str,
) -> &'static str {
    if matches!(active_defense, "defense_effective_extending") {
        return "keep_current_automation_and_watch_decay";
    }
    if matches!(active_defense, "defense_relaxing") {
        return "observe_for_rebound";
    }
    match (severity, primary_pressure) {
        ("critical", "tls_handshake_resource") | ("high", "tls_handshake_resource") => {
            "prioritize_tls_pre_admission_and_handshake_budget"
        }
        ("critical", "idle_connection_resource") | ("high", "idle_connection_resource") => {
            "prioritize_idle_connection_shedding"
        }
        ("critical", "connection_admission") | ("high", "connection_admission") => {
            "prioritize_pre_admission_rejection"
        }
        (_, "event_persistence") => "keep_event_aggregation_and_preserve_samples",
        ("normal", _) => "no_action_required",
        _ => "continue_adaptive_monitoring",
    }
}

fn build_attack_summary(
    severity: &str,
    primary_pressure: &str,
    active_defense: &str,
    top_cluster: Option<&ResourceSentinelClusterSnapshot>,
) -> String {
    let cluster_text = top_cluster
        .map(|cluster| {
            format!(
                "最热簇为 {}，类型 {}，样本 IP {}，累计 {} 次、风险分 {}。",
                cluster.cluster,
                cluster.attack_type,
                cluster.sample_ip,
                cluster.count,
                cluster.score
            )
        })
        .unwrap_or_else(|| "当前没有明显热点攻击簇。".to_string());
    format!(
        "哨兵级别为 {severity}，主要压力判断为 {primary_pressure}，自动防御状态为 {active_defense}。{cluster_text}"
    )
}

fn should_emit_attack_audit(
    diagnosis: &ResourceSentinelAttackDiagnosis,
    lifecycle: &ResourceSentinelAttackLifecycle,
) -> bool {
    if matches!(
        lifecycle.phase.as_str(),
        "started" | "sustained" | "mitigating" | "ended"
    ) {
        return true;
    }
    matches!(diagnosis.severity.as_str(), "high" | "critical")
        || matches!(
            diagnosis.active_defense.as_str(),
            "defense_effective_extending" | "defense_relaxing"
        )
}

fn attack_audit_signature(
    diagnosis: &ResourceSentinelAttackDiagnosis,
    lifecycle: &ResourceSentinelAttackLifecycle,
) -> u64 {
    let mut hasher = DefaultHasher::new();
    lifecycle.phase.hash(&mut hasher);
    diagnosis.severity.hash(&mut hasher);
    diagnosis.primary_pressure.hash(&mut hasher);
    diagnosis.active_defense.hash(&mut hasher);
    diagnosis.recommended_next_action.hash(&mut hasher);
    if let Some(cluster) = diagnosis.top_cluster.as_ref() {
        cluster.cluster.hash(&mut hasher);
        cluster.attack_type.hash(&mut hasher);
        cluster.transport.hash(&mut hasher);
        cluster.reason.hash(&mut hasher);
    }
    hasher.finish()
}

fn build_attack_audit_event(snapshot: ResourceSentinelSnapshot) -> SecurityEventRecord {
    let diagnosis = snapshot.attack_diagnosis;
    let lifecycle = snapshot.attack_lifecycle;
    let sample_ip = diagnosis
        .top_cluster
        .as_ref()
        .map(|cluster| cluster.sample_ip.clone())
        .unwrap_or_else(|| "0.0.0.0".to_string());
    let mut event = SecurityEventRecord::now(
        "SYSTEM",
        "alert",
        format!(
            "resource sentinel attack diagnosis: phase={} severity={} primary_pressure={} active_defense={} recommended_next_action={}",
            lifecycle.phase,
            diagnosis.severity,
            diagnosis.primary_pressure,
            diagnosis.active_defense,
            diagnosis.recommended_next_action
        ),
        sample_ip,
        "0.0.0.0",
        0,
        0,
        "SYSTEM",
    );
    event.provider = Some("resource_sentinel".to_string());
    event.details_json = serde_json::to_string(&serde_json::json!({
        "kind": "resource_sentinel_attack_audit",
        "diagnosis": diagnosis,
        "lifecycle": lifecycle,
        "session": snapshot.attack_session,
        "mode": snapshot.mode,
        "attack_score": snapshot.attack_score,
        "tracked_debt_buckets": snapshot.tracked_debt_buckets,
        "high_debt_buckets": snapshot.high_debt_buckets,
        "extreme_debt_buckets": snapshot.extreme_debt_buckets,
        "tracked_attack_clusters": snapshot.tracked_attack_clusters,
        "active_cooldowns": snapshot.active_cooldowns,
        "pre_admission_rejections": snapshot.pre_admission_rejections,
        "aggregated_events": snapshot.aggregated_events,
        "automated_defense_actions": snapshot.automated_defense_actions,
        "automated_defense_extensions": snapshot.automated_defense_extensions,
        "automated_defense_relaxations": snapshot.automated_defense_relaxations,
        "automated_defense_memory_hits": snapshot.automated_defense_memory_hits,
        "top_attack_clusters": snapshot.top_attack_clusters,
        "defense_action_effects": snapshot.defense_action_effects,
        "defense_decision_traces": snapshot.defense_decision_traces,
        "ingress_gap_analysis": snapshot.ingress_gap_analysis,
        "resource_pressure_feedback": snapshot.resource_pressure_feedback,
        "attack_migrations": snapshot.attack_migrations,
        "attack_report_preview": snapshot.attack_report_preview,
        "cdn_rust_count_note": "CDN 请求数可能远高于 Rust 记录数，因为 CDN/L4/L7 会在不同层提前拦截，Rust 本地审计只代表到达本进程或本进程已聚合的后端视角。"
    }))
    .ok();
    event
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

    #[test]
    fn hot_event_cluster_activates_cluster_cooldown_before_debt_builds() {
        let sentinel = ResourceSentinel::new();
        for index in 1..=10 {
            let event = SecurityEventRecord::now(
                "L4",
                "alert",
                "tls handshake timed out before first request",
                format!("203.0.113.{index}"),
                "192.0.2.10",
                44321,
                443,
                "TCP",
            );
            let _ = sentinel.should_aggregate_security_event(&event);
        }

        let decision = sentinel.admit_connection("203.0.113.200".parse().unwrap(), "tls", 128, 0);
        assert!(!decision.allow);
        assert!(decision
            .reason
            .as_deref()
            .unwrap_or_default()
            .contains("hot_slow_tls_cluster"));
        assert!(sentinel.snapshot().automated_defense_actions >= 1);
    }

    #[test]
    fn slow_tls_hot_cluster_uses_tls_scoped_admission_action() {
        let sentinel = ResourceSentinel::new();
        activate_hot_tls_cluster(&sentinel);

        let tcp_decision =
            sentinel.admit_connection("203.0.113.200".parse().unwrap(), "tcp", 128, 0);
        assert!(tcp_decision.allow);

        let tls_decision =
            sentinel.admit_connection("203.0.113.201".parse().unwrap(), "tls", 128, 0);
        assert!(!tls_decision.allow);
        assert!(tls_decision
            .reason
            .as_deref()
            .unwrap_or_default()
            .contains("hot_slow_tls_cluster"));
    }

    #[test]
    fn low_frequency_event_cluster_does_not_activate_cluster_cooldown() {
        let sentinel = ResourceSentinel::new();
        for index in 1..=2 {
            let event = SecurityEventRecord::now(
                "L4",
                "alert",
                "tls handshake timed out before first request",
                format!("203.0.113.{index}"),
                "192.0.2.10",
                44321,
                443,
                "TCP",
            );
            let _ = sentinel.should_aggregate_security_event(&event);
        }

        let decision = sentinel.admit_connection("203.0.113.200".parse().unwrap(), "tls", 128, 0);
        assert!(decision.allow);
        assert_eq!(sentinel.snapshot().automated_defense_actions, 0);
    }

    #[test]
    fn active_defense_extends_when_cooldown_is_still_rejecting_under_pressure() {
        let sentinel = ResourceSentinel::new();
        activate_hot_tls_cluster(&sentinel);
        let key = "transport:tls:cluster:203.0.113.0/24";
        let bucket = sentinel
            .cooldowns
            .get(key)
            .expect("hot cluster should create cooldown");
        let before_until = bucket.until_ms.load(Ordering::Relaxed);
        let eval_at = bucket
            .created_ms
            .saturating_add(DEFENSE_EFFECT_EVAL_INTERVAL_MS + 1);
        drop(bucket);

        sentinel
            .attack_score
            .store(SCORE_UNDER_ATTACK, Ordering::Relaxed);
        sentinel
            .pre_admission_rejections
            .fetch_add(DEFENSE_EFFECT_REJECTION_DELTA, Ordering::Relaxed);
        sentinel.evaluate_defense_effects(eval_at);

        let bucket = sentinel
            .cooldowns
            .get(key)
            .expect("cooldown should still exist");
        assert!(bucket.until_ms.load(Ordering::Relaxed) > before_until);
        assert_eq!(bucket.extensions.load(Ordering::Relaxed), 1);
        let snapshot = sentinel.snapshot();
        assert_eq!(snapshot.automated_defense_extensions, 1);
        assert_eq!(
            snapshot.defense_action_effects[0].attack_type,
            "slow_tls_handshake"
        );
        assert_eq!(snapshot.defense_action_effects[0].last_outcome, "effective");
        assert_eq!(
            snapshot.defense_action_effects[0].last_rejection_delta,
            DEFENSE_EFFECT_REJECTION_DELTA
        );
        assert_eq!(snapshot.defense_action_effects[0].confidence, 100);
    }

    #[test]
    fn effective_action_memory_is_reused_for_matching_attack_type() {
        let sentinel = ResourceSentinel::new();
        activate_hot_tls_cluster(&sentinel);
        let key = "transport:tls:cluster:203.0.113.0/24";
        let bucket = sentinel
            .cooldowns
            .get(key)
            .expect("hot TLS cluster should create scoped cooldown");
        let eval_at = bucket
            .created_ms
            .saturating_add(DEFENSE_EFFECT_EVAL_INTERVAL_MS + 1);
        drop(bucket);

        sentinel
            .attack_score
            .store(SCORE_UNDER_ATTACK, Ordering::Relaxed);
        sentinel
            .pre_admission_rejections
            .fetch_add(DEFENSE_EFFECT_REJECTION_DELTA, Ordering::Relaxed);
        sentinel.evaluate_defense_effects(eval_at);

        let event = SecurityEventRecord::now(
            "L4",
            "alert",
            "tls handshake timed out before first request",
            "203.0.113.99",
            "192.0.2.10",
            44321,
            443,
            "TCP",
        );
        let _ = sentinel.should_aggregate_security_event(&event);
        assert!(sentinel.snapshot().automated_defense_memory_hits >= 1);
    }

    #[test]
    fn attack_diagnosis_summarizes_primary_tls_pressure_and_defense_effect() {
        let sentinel = ResourceSentinel::new();
        activate_hot_tls_cluster(&sentinel);
        let key = "transport:tls:cluster:203.0.113.0/24";
        let bucket = sentinel
            .cooldowns
            .get(key)
            .expect("hot TLS cluster should create scoped cooldown");
        let eval_at = bucket
            .created_ms
            .saturating_add(DEFENSE_EFFECT_EVAL_INTERVAL_MS + 1);
        drop(bucket);

        sentinel
            .attack_score
            .store(SCORE_UNDER_ATTACK, Ordering::Relaxed);
        sentinel
            .pre_admission_rejections
            .fetch_add(DEFENSE_EFFECT_REJECTION_DELTA, Ordering::Relaxed);
        sentinel.evaluate_defense_effects(eval_at);

        let diagnosis = sentinel.snapshot().attack_diagnosis;
        assert_eq!(diagnosis.severity, "high");
        assert_eq!(diagnosis.primary_pressure, "tls_handshake_resource");
        assert_eq!(diagnosis.active_defense, "defense_effective_extending");
        assert_eq!(
            diagnosis.recommended_next_action,
            "keep_current_automation_and_watch_decay"
        );
        assert!(diagnosis.summary.contains("slow_tls_handshake"));
        assert!(diagnosis
            .evidence
            .iter()
            .any(|item| item.contains("pre_admission_rejections")));
    }

    #[test]
    fn attack_audit_event_captures_diagnosis_and_cdn_rust_gap_note() {
        let sentinel = ResourceSentinel::new();
        activate_hot_tls_cluster(&sentinel);
        let key = "transport:tls:cluster:203.0.113.0/24";
        let bucket = sentinel
            .cooldowns
            .get(key)
            .expect("hot TLS cluster should create scoped cooldown");
        let eval_at = bucket
            .created_ms
            .saturating_add(DEFENSE_EFFECT_EVAL_INTERVAL_MS + 1);
        drop(bucket);

        sentinel
            .attack_score
            .store(SCORE_UNDER_ATTACK, Ordering::Relaxed);
        sentinel
            .pre_admission_rejections
            .fetch_add(DEFENSE_EFFECT_REJECTION_DELTA, Ordering::Relaxed);
        sentinel.evaluate_defense_effects(eval_at);

        let event = sentinel
            .maybe_attack_audit_event()
            .expect("high diagnosis should emit audit event");
        assert_eq!(event.layer, "SYSTEM");
        assert_eq!(event.provider.as_deref(), Some("resource_sentinel"));
        assert!(event.reason.contains("tls_handshake_resource"));
        let details = event
            .details_json
            .expect("audit event should include details");
        assert!(details.contains("resource_sentinel_attack_audit"));
        assert!(details.contains("\"session\""));
        assert!(details.contains("\"defense_decision_traces\""));
        assert!(details.contains("CDN"));
        assert!(details.contains("Rust"));
        assert!(sentinel.maybe_attack_audit_event().is_none());
        assert_eq!(sentinel.snapshot().automated_audit_events, 1);
    }

    #[test]
    fn attack_lifecycle_tracks_start_mitigation_and_end() {
        let sentinel = ResourceSentinel::new();
        let started_diagnosis = ResourceSentinelAttackDiagnosis {
            severity: "high".to_string(),
            active_defense: "cooldown_active".to_string(),
            ..Default::default()
        };
        let started = sentinel.update_attack_lifecycle(&started_diagnosis);
        assert_eq!(started.phase, "started");
        assert_eq!(started.previous_phase, "normal");
        assert!(started.transitioned);

        let mitigating_diagnosis = ResourceSentinelAttackDiagnosis {
            severity: "elevated".to_string(),
            active_defense: "defense_relaxing".to_string(),
            ..Default::default()
        };
        let mitigating = sentinel.update_attack_lifecycle(&mitigating_diagnosis);
        assert_eq!(mitigating.phase, "mitigating");
        assert_eq!(mitigating.previous_phase, "started");
        assert!(mitigating.transitioned);

        let ended_diagnosis = ResourceSentinelAttackDiagnosis {
            severity: "normal".to_string(),
            active_defense: "monitoring".to_string(),
            ..Default::default()
        };
        let ended = sentinel.update_attack_lifecycle(&ended_diagnosis);
        assert_eq!(ended.phase, "ended");
        assert_eq!(ended.previous_phase, "mitigating");
        assert!(ended.transitioned);
    }

    #[test]
    fn attack_session_summarizes_lifecycle_timeline() {
        let sentinel = ResourceSentinel::new();
        activate_hot_tls_cluster(&sentinel);
        sentinel
            .attack_score
            .store(SCORE_UNDER_ATTACK, Ordering::Relaxed);

        let started_snapshot = sentinel.snapshot();
        assert_eq!(started_snapshot.attack_lifecycle.phase, "started");
        assert_eq!(started_snapshot.attack_session.session_id, 1);

        sentinel
            .attack_score
            .store(SCORE_SURVIVAL, Ordering::Relaxed);
        sentinel
            .pre_admission_rejections
            .fetch_add(9, Ordering::Relaxed);
        sentinel.aggregated_events.fetch_add(5, Ordering::Relaxed);
        sentinel
            .automated_defense_actions
            .fetch_add(3, Ordering::Relaxed);
        sentinel
            .automated_defense_extensions
            .fetch_add(1, Ordering::Relaxed);
        sentinel
            .automated_defense_relaxations
            .fetch_add(1, Ordering::Relaxed);
        sentinel
            .automated_audit_events
            .fetch_add(2, Ordering::Relaxed);

        let sustained_snapshot = sentinel.snapshot();
        let session = sustained_snapshot.attack_session;
        assert_eq!(sustained_snapshot.attack_lifecycle.phase, "sustained");
        assert_eq!(session.session_id, 1);
        assert_eq!(session.phase, "sustained");
        assert_eq!(session.peak_severity, "critical");
        assert_eq!(session.peak_attack_score, SCORE_SURVIVAL);
        assert_eq!(session.defense_actions, 3);
        assert_eq!(session.defense_extensions, 1);
        assert_eq!(session.defense_relaxations, 1);
        assert_eq!(session.audit_event_count, 2);
        assert_eq!(session.pre_admission_rejections, 9);
        assert_eq!(session.aggregated_events, 5);
        assert_eq!(session.top_clusters[0].attack_type, "slow_tls_handshake");
        assert!(session.summary.contains("攻击会话 #1"));

        let ended_diagnosis = ResourceSentinelAttackDiagnosis {
            severity: "normal".to_string(),
            active_defense: "monitoring".to_string(),
            primary_pressure: "stable".to_string(),
            ..Default::default()
        };
        let ended_lifecycle = sentinel.update_attack_lifecycle(&ended_diagnosis);
        let ended_session = sentinel.attack_session_snapshot(
            0,
            sentinel.pre_admission_rejections.load(Ordering::Relaxed),
            sentinel.aggregated_events.load(Ordering::Relaxed),
            sentinel.automated_defense_actions.load(Ordering::Relaxed),
            sentinel
                .automated_defense_extensions
                .load(Ordering::Relaxed),
            sentinel
                .automated_defense_relaxations
                .load(Ordering::Relaxed),
            sentinel.automated_audit_events.load(Ordering::Relaxed),
            &ended_diagnosis,
            &ended_lifecycle,
            &sustained_snapshot.top_attack_clusters,
        );
        assert_eq!(ended_lifecycle.phase, "ended");
        assert_eq!(ended_session.final_outcome, "recovered");
        assert!(ended_session.ended_at_ms.is_some());
    }

    #[test]
    fn active_defense_relaxes_when_pressure_disappears() {
        let sentinel = ResourceSentinel::new();
        activate_hot_tls_cluster(&sentinel);
        let key = "transport:tls:cluster:203.0.113.0/24";
        let bucket = sentinel
            .cooldowns
            .get(key)
            .expect("hot cluster should create cooldown");
        let before_until = bucket.until_ms.load(Ordering::Relaxed);
        let eval_at = bucket
            .created_ms
            .saturating_add(DEFENSE_EFFECT_EVAL_INTERVAL_MS + 1);
        drop(bucket);

        sentinel.attack_score.store(0, Ordering::Relaxed);
        sentinel.evaluate_defense_effects(eval_at);

        let bucket = sentinel
            .cooldowns
            .get(key)
            .expect("cooldown should still exist");
        let after_until = bucket.until_ms.load(Ordering::Relaxed);
        assert!(after_until < before_until);
        assert!(after_until <= eval_at.saturating_add(DEFENSE_EFFECT_RELAX_TO_MS));
        assert_eq!(bucket.relaxations.load(Ordering::Relaxed), 1);
        let snapshot = sentinel.snapshot();
        assert_eq!(snapshot.automated_defense_relaxations, 1);
        assert_eq!(snapshot.defense_action_effects[0].last_outcome, "recovered");
        assert_eq!(snapshot.defense_action_effects[0].ineffective_score, 0);
    }

    #[test]
    fn defense_action_effect_scoring_marks_harmful_when_pressure_rises_without_rejections() {
        let sentinel = ResourceSentinel::new();
        activate_hot_tls_cluster(&sentinel);
        let key = "transport:tls:cluster:203.0.113.0/24";
        let bucket = sentinel
            .cooldowns
            .get(key)
            .expect("hot cluster should create cooldown");
        bucket
            .last_attack_score
            .store(SCORE_ELEVATED, Ordering::Relaxed);
        let eval_at = bucket
            .created_ms
            .saturating_add(DEFENSE_EFFECT_EVAL_INTERVAL_MS + 1);
        drop(bucket);

        sentinel
            .attack_score
            .store(SCORE_UNDER_ATTACK, Ordering::Relaxed);
        sentinel.evaluate_defense_effects(eval_at);

        let snapshot = sentinel.snapshot();
        assert_eq!(snapshot.defense_action_effects[0].last_outcome, "harmful");
        assert_eq!(snapshot.defense_action_effects[0].harmful_score, 1);
        assert_eq!(snapshot.defense_action_effects[0].ineffective_score, 1);
        assert_eq!(
            snapshot.defense_action_effects[0].last_score_delta,
            SCORE_UNDER_ATTACK as i64 - SCORE_ELEVATED as i64
        );
    }

    #[test]
    fn defense_strategy_selector_switches_away_from_harmful_tls_action() {
        let sentinel = ResourceSentinel::new();
        let ip: IpAddr = "203.0.113.99".parse().unwrap();
        sentinel.note_defense_effect(
            "slow_tls_handshake",
            DEFENSE_ACTION_TLS_PRE_ADMISSION,
            DEFENSE_OUTCOME_HARMFUL,
            0,
            SCORE_UNDER_ATTACK as i64,
        );

        let plan = sentinel
            .defense_plan(ip, "slow_tls_handshake", MODE_UNDER_ATTACK)
            .expect("harmful TLS action should fall back to broader cluster plan");
        assert_eq!(plan.action, DEFENSE_ACTION_CLUSTER_CONNECTION);
        assert_eq!(plan.key, "cluster:203.0.113.0/24");
        let snapshot = sentinel.snapshot();
        assert_eq!(snapshot.automated_defense_memory_hits, 1);
        assert_eq!(
            snapshot.defense_decision_traces[0].reason,
            "harmful_memory_switched"
        );
        assert_eq!(
            snapshot.defense_decision_traces[0].selected_action,
            DEFENSE_ACTION_CLUSTER_CONNECTION
        );
        assert!(snapshot.defense_decision_traces[0].switched_action);
    }

    #[test]
    fn defense_strategy_selector_reuses_effective_cluster_action() {
        let sentinel = ResourceSentinel::new();
        let ip: IpAddr = "203.0.113.99".parse().unwrap();
        sentinel.note_defense_effect(
            "slow_tls_handshake",
            DEFENSE_ACTION_CLUSTER_CONNECTION,
            DEFENSE_OUTCOME_EFFECTIVE,
            DEFENSE_EFFECT_REJECTION_DELTA,
            -10,
        );

        let plan = sentinel
            .defense_plan(ip, "slow_tls_handshake", MODE_ELEVATED)
            .expect("effective remembered action should be reused");
        assert_eq!(plan.action, DEFENSE_ACTION_CLUSTER_CONNECTION);
        let trace = &sentinel.snapshot().defense_decision_traces[0];
        assert_eq!(trace.reason, "effective_memory_reused");
        assert_eq!(trace.default_action, DEFENSE_ACTION_TLS_PRE_ADMISSION);
        assert_eq!(trace.selected_action, DEFENSE_ACTION_CLUSTER_CONNECTION);
        assert!(trace.used_memory);
        assert!(trace.switched_action);
    }

    #[test]
    fn defense_decision_trace_records_default_and_unsupported_choices() {
        let sentinel = ResourceSentinel::new();
        let ip: IpAddr = "203.0.113.99".parse().unwrap();

        let plan = sentinel
            .defense_plan(ip, "idle_no_request", MODE_ELEVATED)
            .expect("idle attack should have a default cluster plan");
        assert_eq!(plan.action, DEFENSE_ACTION_CLUSTER_CONNECTION);
        let default_trace = &sentinel.snapshot().defense_decision_traces[0];
        assert_eq!(default_trace.reason, "default_without_memory");
        assert_eq!(
            default_trace.selected_action,
            DEFENSE_ACTION_CLUSTER_CONNECTION
        );
        assert!(!default_trace.used_memory);

        assert!(sentinel
            .defense_plan(ip, "provider_intercept", MODE_UNDER_ATTACK)
            .is_none());
        let snapshot = sentinel.snapshot();
        let unsupported_trace = snapshot
            .defense_decision_traces
            .iter()
            .find(|trace| trace.attack_type == "provider_intercept")
            .expect("unsupported attack type should still explain the decision");
        assert_eq!(unsupported_trace.reason, "unsupported_attack_type");
        assert_eq!(unsupported_trace.selected_action, "none");
    }

    #[test]
    fn attack_replay_fixture_generates_report_gap_and_fast_path_feedback() {
        let sentinel = ResourceSentinel::new();
        activate_hot_tls_cluster(&sentinel);
        sentinel
            .attack_score
            .store(SCORE_SURVIVAL, Ordering::Relaxed);
        sentinel
            .pre_admission_rejections
            .fetch_add(400_000, Ordering::Relaxed);
        sentinel
            .aggregated_events
            .fetch_add(20_000, Ordering::Relaxed);

        let mut pressure = RuntimePressureSnapshot {
            level: "attack",
            capacity_class: "large",
            defense_depth: "full",
            server_mode: "survival",
            server_mode_scale_percent: 60,
            server_mode_reason: "attack_or_queue_saturation",
            storage_queue_usage_percent: 95,
            cpu_usage_percent: 0.0,
            cpu_pressure_score: 0,
            cpu_sample_available: false,
            drop_delay: false,
            trim_event_persistence: false,
            l7_bucket_limit: 1_000,
            l7_page_window_limit: 1_000,
            behavior_bucket_limit: 1_000,
            behavior_sample_stride: 1,
            prefer_drop: false,
        };
        sentinel.apply_runtime_pressure(&mut pressure);

        let snapshot = sentinel.snapshot();
        assert_eq!(snapshot.attack_lifecycle.phase, "started");
        assert_eq!(
            snapshot.ingress_gap_analysis.likely_absorption_layer,
            "transport_or_cdn_edge"
        );
        assert_eq!(
            snapshot.resource_pressure_feedback.resource_outcome,
            "fast_path_guard_active"
        );
        assert!(snapshot.attack_report_preview.is_some());
        assert!(snapshot
            .attack_report_preview
            .as_ref()
            .expect("report")
            .recommendations
            .iter()
            .any(|item| item.contains("fast path")));
    }

    #[test]
    fn defense_memory_restore_rehydrates_strategy_selection() {
        let sentinel = ResourceSentinel::new();
        let ip: IpAddr = "203.0.113.99".parse().unwrap();
        sentinel.restore_defense_memory(
            "slow_tls_handshake",
            DEFENSE_ACTION_CLUSTER_CONNECTION,
            5,
            1,
            0,
            0,
            "effective",
            DEFENSE_EFFECT_REJECTION_DELTA,
            -20,
            now_millis(),
        );

        let plan = sentinel
            .defense_plan(ip, "slow_tls_handshake", MODE_ELEVATED)
            .expect("restored memory should select a plan");
        assert_eq!(plan.action, DEFENSE_ACTION_CLUSTER_CONNECTION);
        let exports = sentinel.defense_memory_exports();
        assert_eq!(
            exports[0].preferred_action,
            DEFENSE_ACTION_CLUSTER_CONNECTION
        );
        assert_eq!(exports[0].last_outcome, "effective");
    }

    fn activate_hot_tls_cluster(sentinel: &ResourceSentinel) {
        for index in 1..=10 {
            let event = SecurityEventRecord::now(
                "L4",
                "alert",
                "tls handshake timed out before first request",
                format!("203.0.113.{index}"),
                "192.0.2.10",
                44321,
                443,
                "TCP",
            );
            let _ = sentinel.should_aggregate_security_event(&event);
        }
    }
}
