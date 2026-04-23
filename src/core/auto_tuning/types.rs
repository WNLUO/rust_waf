use crate::config::{AutoTuningIntent, AutoTuningMode, Config};
use crate::metrics::MetricsSnapshot;

#[derive(Debug, Clone)]
pub struct AutoTuningRecommendationSnapshot {
    pub l4_normal_connection_budget_per_minute: u32,
    pub l4_suspicious_connection_budget_per_minute: u32,
    pub l4_high_risk_connection_budget_per_minute: u32,
    pub l4_reject_threshold_percent: u16,
    pub l4_critical_reject_threshold_percent: u16,
    pub tls_handshake_timeout_ms: u64,
}

#[derive(Debug, Clone)]
pub struct AutoTuningRuntimeSnapshot {
    pub mode: AutoTuningMode,
    pub intent: AutoTuningIntent,
    pub controller_state: String,
    pub detected_cpu_cores: usize,
    pub detected_memory_limit_mb: Option<u64>,
    pub last_adjust_at: Option<i64>,
    pub last_adjust_reason: Option<String>,
    pub last_adjust_diff: Vec<String>,
    pub rollback_count_24h: u32,
    pub cooldown_until: Option<i64>,
    pub last_effect_evaluation: Option<AutoTuningEffectEvaluationSnapshot>,
    pub last_observed_tls_handshake_timeout_rate_percent: f64,
    pub last_observed_bucket_reject_rate_percent: f64,
    pub last_observed_avg_proxy_latency_ms: u64,
    pub last_observed_identity_resolution_pressure_percent: f64,
    pub last_observed_l7_friction_pressure_percent: f64,
    pub last_observed_slow_attack_pressure_percent: f64,
    pub last_observed_direct_idle_no_request_connections: u64,
    pub consecutive_handshake_high: u8,
    pub consecutive_identity_high: u8,
    pub consecutive_slow_attack_high: u8,
    pub consecutive_budget_high: u8,
    pub consecutive_latency_high: u8,
    pub recommendation: AutoTuningRecommendationSnapshot,
}

#[derive(Debug, Clone)]
pub struct AutoTuningEffectEvaluationSnapshot {
    pub status: String,
    pub observed_at: Option<i64>,
    pub sample_requests: u64,
    pub handshake_timeout_rate_delta_percent: f64,
    pub bucket_reject_rate_delta_percent: f64,
    pub avg_proxy_latency_delta_ms: i64,
    pub segments: Vec<AutoTuningEffectSegmentEvaluationSnapshot>,
    pub summary: String,
}

#[derive(Debug, Clone)]
pub struct AutoTuningEffectSegmentEvaluationSnapshot {
    pub scope_type: String,
    pub scope_key: String,
    pub host: Option<String>,
    pub route: Option<String>,
    pub request_kind: String,
    pub sample_requests: u64,
    pub avg_proxy_latency_delta_ms: i64,
    pub failure_rate_delta_percent: f64,
    pub status: String,
}

#[derive(Debug, Clone, Default)]
pub struct AutoTuningControllerState {
    pub last_tick_at: Option<i64>,
    pub cooldown_until: Option<i64>,
    pub last_metrics: Option<MetricsSnapshot>,
    pub consecutive_handshake_high: u8,
    pub consecutive_identity_high: u8,
    pub consecutive_slow_attack_high: u8,
    pub consecutive_budget_high: u8,
    pub consecutive_latency_high: u8,
    pub baseline_before_adjust: Option<Config>,
    pub rollback_timestamps: Vec<i64>,
    pub bootstrap_applied: bool,
    pub(super) pending_effect_evaluation: Option<PendingEffectEvaluation>,
}

#[derive(Debug, Clone)]
pub struct AutoTuningDecision {
    pub next_config: Config,
    pub requires_l4_refresh: bool,
}

#[derive(Debug, Clone)]
pub(super) struct MetricDeltas {
    pub(super) proxied_requests_delta: u64,
    pub(super) proxy_successes_delta: u64,
    pub(super) handshake_timeout_rate_percent: f64,
    pub(super) bucket_reject_rate_percent: f64,
    pub(super) avg_proxy_latency_ms: u64,
    pub(super) identity_resolution_pressure_percent: f64,
    pub(super) l7_friction_pressure_percent: f64,
    pub(super) slow_attack_pressure_percent: f64,
    pub(super) direct_idle_no_request_connections: u64,
    pub(super) segments: Vec<TrafficSegmentDelta>,
}

#[derive(Debug, Clone)]
pub(super) struct PendingEffectEvaluation {
    pub(super) adjust_at: i64,
    pub(super) reason: String,
    pub(super) action_kind: AutoTuningActionKind,
    pub(super) baseline: MetricDeltas,
}

#[derive(Debug, Clone, Copy)]
pub(super) enum AutoTuningActionKind {
    Bootstrap,
    Handshake,
    Identity,
    SlowAttack,
    Budget,
    Latency,
}

#[derive(Debug, Clone)]
pub(super) struct TrafficSegmentDelta {
    pub(super) scope_type: &'static str,
    pub(super) scope_key: String,
    pub(super) host: Option<String>,
    pub(super) route: Option<String>,
    pub(super) request_kind: String,
    pub(super) proxied_requests_delta: u64,
    pub(super) avg_proxy_latency_ms: u64,
    pub(super) failure_rate_percent: f64,
}

#[derive(Debug, Clone)]
pub(super) struct ActionTriggerContext {
    pub(super) reason_code: String,
    pub(super) detail: String,
}
