use crate::config::{AutoTuningIntent, AutoTuningMode, Config};
use crate::metrics::{MetricsSnapshot, ProxyTrafficMetricsSnapshot, ProxyTrafficSegmentSnapshot};
use std::collections::BTreeMap;

use super::system_profile::{detect_system_profile, SystemProfile};

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
    pending_effect_evaluation: Option<PendingEffectEvaluation>,
}

#[derive(Debug, Clone)]
pub struct AutoTuningDecision {
    pub next_config: Config,
    pub requires_l4_refresh: bool,
}

#[derive(Debug, Clone)]
struct MetricDeltas {
    proxied_requests_delta: u64,
    proxy_successes_delta: u64,
    handshake_timeout_rate_percent: f64,
    bucket_reject_rate_percent: f64,
    avg_proxy_latency_ms: u64,
    identity_resolution_pressure_percent: f64,
    l7_friction_pressure_percent: f64,
    slow_attack_pressure_percent: f64,
    direct_idle_no_request_connections: u64,
    segments: Vec<TrafficSegmentDelta>,
}

#[derive(Debug, Clone)]
struct PendingEffectEvaluation {
    adjust_at: i64,
    reason: String,
    action_kind: AutoTuningActionKind,
    baseline: MetricDeltas,
}

#[derive(Debug, Clone, Copy)]
enum AutoTuningActionKind {
    Bootstrap,
    Handshake,
    Identity,
    SlowAttack,
    Budget,
    Latency,
}

#[derive(Debug, Clone)]
struct TrafficSegmentDelta {
    scope_type: &'static str,
    scope_key: String,
    host: Option<String>,
    route: Option<String>,
    request_kind: String,
    proxied_requests_delta: u64,
    avg_proxy_latency_ms: u64,
    failure_rate_percent: f64,
}

#[derive(Debug, Clone)]
struct ActionTriggerContext {
    reason_code: String,
    detail: String,
}

pub fn build_runtime_snapshot(config: &Config) -> AutoTuningRuntimeSnapshot {
    let profile = detect_system_profile();
    let recommendation = recommend(config, &profile);

    AutoTuningRuntimeSnapshot {
        mode: config.auto_tuning.mode,
        intent: config.auto_tuning.intent,
        controller_state: controller_state_label(config.auto_tuning.mode).to_string(),
        detected_cpu_cores: profile.cpu_cores,
        detected_memory_limit_mb: profile
            .memory_limit_bytes
            .map(|value| value / (1024 * 1024)),
        last_adjust_at: None,
        last_adjust_reason: Some("phase1_bootstrap_estimate".to_string()),
        last_adjust_diff: Vec::new(),
        rollback_count_24h: 0,
        cooldown_until: None,
        last_effect_evaluation: None,
        last_observed_tls_handshake_timeout_rate_percent: 0.0,
        last_observed_bucket_reject_rate_percent: 0.0,
        last_observed_avg_proxy_latency_ms: 0,
        last_observed_identity_resolution_pressure_percent: 0.0,
        last_observed_l7_friction_pressure_percent: 0.0,
        last_observed_slow_attack_pressure_percent: 0.0,
        last_observed_direct_idle_no_request_connections: 0,
        recommendation,
    }
}

pub fn refresh_runtime_snapshot(runtime: &mut AutoTuningRuntimeSnapshot, config: &Config) {
    let profile = detect_system_profile();
    runtime.mode = config.auto_tuning.mode;
    runtime.intent = config.auto_tuning.intent;
    runtime.detected_cpu_cores = profile.cpu_cores;
    runtime.detected_memory_limit_mb = profile
        .memory_limit_bytes
        .map(|value| value / (1024 * 1024));
    runtime.recommendation = recommend(config, &profile);
    if runtime.controller_state.is_empty() {
        runtime.controller_state = controller_state_label(config.auto_tuning.mode).to_string();
    }
}

pub fn run_control_step(
    config: &Config,
    runtime: &mut AutoTuningRuntimeSnapshot,
    state: &mut AutoTuningControllerState,
    metrics: &MetricsSnapshot,
    now: i64,
) -> Option<AutoTuningDecision> {
    runtime.mode = config.auto_tuning.mode;
    runtime.intent = config.auto_tuning.intent;

    if !should_tick(config, state, now) {
        return None;
    }

    runtime.recommendation = recommend(config, &detect_system_profile());

    prune_rollback_timestamps(state, now);
    runtime.rollback_count_24h = state.rollback_timestamps.len() as u32;

    let deltas = match state.last_metrics.as_ref() {
        Some(previous) => compute_deltas(previous, metrics),
        None => {
            state.last_metrics = Some(metrics.clone());
            runtime.controller_state = "warming_up".to_string();
            return None;
        }
    };
    state.last_metrics = Some(metrics.clone());

    runtime.last_observed_tls_handshake_timeout_rate_percent =
        deltas.handshake_timeout_rate_percent;
    runtime.last_observed_bucket_reject_rate_percent = deltas.bucket_reject_rate_percent;
    runtime.last_observed_avg_proxy_latency_ms = deltas.avg_proxy_latency_ms;
    runtime.last_observed_identity_resolution_pressure_percent =
        deltas.identity_resolution_pressure_percent;
    runtime.last_observed_l7_friction_pressure_percent = deltas.l7_friction_pressure_percent;
    runtime.last_observed_slow_attack_pressure_percent = deltas.slow_attack_pressure_percent;
    runtime.last_observed_direct_idle_no_request_connections =
        deltas.direct_idle_no_request_connections;
    maybe_finalize_effect_evaluation(config, runtime, state, &deltas, now);

    if matches!(config.auto_tuning.mode, AutoTuningMode::Off) {
        runtime.controller_state = "disabled".to_string();
        state.consecutive_handshake_high = 0;
        state.consecutive_identity_high = 0;
        state.consecutive_budget_high = 0;
        state.consecutive_latency_high = 0;
        state.baseline_before_adjust = None;
        state.bootstrap_applied = false;
        return None;
    }

    let rollback_context = state
        .pending_effect_evaluation
        .as_ref()
        .and_then(|pending| rollback_trigger_context(config, &pending.baseline, &deltas));

    if let Some(cooldown_until) = state.cooldown_until {
        if now < cooldown_until {
            if should_rollback(config, state, &deltas) {
                let mut rollback_config = state
                    .baseline_before_adjust
                    .take()
                    .unwrap_or_else(|| config.clone());
                rollback_config.auto_tuning = config.auto_tuning.clone();
                rollback_config = rollback_config.normalized();

                let rollback_cooldown_until =
                    Some(now + (config.auto_tuning.cooldown_secs as i64).saturating_mul(2));
                state.cooldown_until = rollback_cooldown_until;
                state.rollback_timestamps.push(now);
                runtime.rollback_count_24h = state.rollback_timestamps.len() as u32;

                runtime.controller_state = "rollback".to_string();
                runtime.last_adjust_at = Some(now);
                runtime.last_adjust_reason = Some(
                    rollback_context
                        .as_ref()
                        .map(|context| context.reason_code.clone())
                        .unwrap_or_else(|| "rollback_due_to_metric_regression".to_string()),
                );
                runtime.last_adjust_diff = vec![
                    "restored previous stable runtime config".to_string(),
                    rollback_context
                        .as_ref()
                        .map(|context| context.detail.clone())
                        .unwrap_or_else(|| "rollback triggered by metric regression".to_string()),
                ];
                runtime.cooldown_until = rollback_cooldown_until;
                runtime.last_effect_evaluation =
                    Some(rollback_effect_snapshot(state, &deltas, now));

                state.consecutive_handshake_high = 0;
                state.consecutive_identity_high = 0;
                state.consecutive_budget_high = 0;
                state.consecutive_latency_high = 0;

                return Some(AutoTuningDecision {
                    next_config: rollback_config,
                    requires_l4_refresh: true,
                });
            }
            runtime.cooldown_until = Some(cooldown_until);
            runtime.controller_state = "cooldown".to_string();
            return None;
        }
        state.cooldown_until = None;
        // Cooldown ended and no rollback was triggered: treat current config as stable.
        state.baseline_before_adjust = None;
        runtime.cooldown_until = None;
    }

    if should_rollback(config, state, &deltas) {
        let mut rollback_config = state
            .baseline_before_adjust
            .take()
            .unwrap_or_else(|| config.clone());
        rollback_config.auto_tuning = config.auto_tuning.clone();
        rollback_config = rollback_config.normalized();

        let cooldown_until =
            Some(now + (config.auto_tuning.cooldown_secs as i64).saturating_mul(2));
        state.cooldown_until = cooldown_until;
        state.rollback_timestamps.push(now);
        runtime.rollback_count_24h = state.rollback_timestamps.len() as u32;

        runtime.controller_state = "rollback".to_string();
        runtime.last_adjust_at = Some(now);
        runtime.last_adjust_reason = Some(
            rollback_context
                .as_ref()
                .map(|context| context.reason_code.clone())
                .unwrap_or_else(|| "rollback_due_to_metric_regression".to_string()),
        );
        runtime.last_adjust_diff = vec![
            "restored previous stable runtime config".to_string(),
            rollback_context
                .as_ref()
                .map(|context| context.detail.clone())
                .unwrap_or_else(|| "rollback triggered by metric regression".to_string()),
        ];
        runtime.cooldown_until = cooldown_until;
        runtime.last_effect_evaluation = Some(rollback_effect_snapshot(state, &deltas, now));

        state.consecutive_handshake_high = 0;
        state.consecutive_identity_high = 0;
        state.consecutive_slow_attack_high = 0;
        state.consecutive_budget_high = 0;
        state.consecutive_latency_high = 0;

        return Some(AutoTuningDecision {
            next_config: rollback_config,
            requires_l4_refresh: true,
        });
    }

    if matches!(config.auto_tuning.mode, AutoTuningMode::Active) && !state.bootstrap_applied {
        if let Some(decision) = apply_bootstrap_recommendation(config, runtime, state, now) {
            return Some(decision);
        }
        state.bootstrap_applied = true;
    }

    update_consecutive_counters(config, state, &deltas);

    let action = if state.consecutive_handshake_high >= 3 {
        Some("handshake")
    } else if state.consecutive_slow_attack_high >= 3 {
        Some("slow_attack")
    } else if state.consecutive_identity_high >= 3 {
        Some("identity")
    } else if state.consecutive_budget_high >= 3 {
        Some("budget")
    } else if state.consecutive_latency_high >= 3 {
        Some("latency")
    } else {
        None
    };

    let Some(action) = action else {
        runtime.controller_state = "stable".to_string();
        return None;
    };
    let dominant_segment = dominant_segment_for_action(action, &deltas);
    let action_context = action_trigger_context(config, action, &deltas, dominant_segment);

    if matches!(config.auto_tuning.mode, AutoTuningMode::Observe)
        || !config.auto_tuning.runtime_adjust_enabled
    {
        runtime.controller_state = "observe_pending_adjust".to_string();
        runtime.last_adjust_reason = Some(
            action_context
                .as_ref()
                .map(|context| format!("would_{}", context.reason_code))
                .unwrap_or_else(|| format!("would_adjust_for_{}", action)),
        );
        runtime.last_adjust_diff = action_context
            .as_ref()
            .map(|context| vec![context.detail.clone()])
            .unwrap_or_default();
        return None;
    }

    let mut next = config.clone();
    let mut diff = Vec::new();
    let mut touched_l4 = false;

    state.baseline_before_adjust = Some(config.clone());

    match action {
        "handshake" => {
            if !is_pinned(config, "l7_config.tls_handshake_timeout_ms") {
                let before = next.l7_config.tls_handshake_timeout_ms;
                next.l7_config.tls_handshake_timeout_ms = adjust_u64(
                    before,
                    config.auto_tuning.max_step_percent,
                    true,
                    500,
                    60_000,
                );
                diff.push(format!(
                    "l7_config.tls_handshake_timeout_ms: {} -> {}",
                    before, next.l7_config.tls_handshake_timeout_ms
                ));
            }
            touched_l4 |= adjust_l4_reject_thresholds(&mut next, config, &mut diff, true);
        }
        "identity" => {
            touched_l4 |= adjust_l4_budgets(&mut next, config, &mut diff, false);
            touched_l4 |= adjust_l4_reject_thresholds(&mut next, config, &mut diff, false);
            adjust_cc_route_thresholds(&mut next, config, &mut diff, false);
            adjust_cc_host_thresholds(&mut next, config, &mut diff, false);
            adjust_cc_ip_thresholds(&mut next, config, &mut diff, false);
            adjust_cc_delay_ms(&mut next, config, &mut diff, true);
        }
        "slow_attack" => {
            adjust_tls_handshake_timeout_ms(&mut next, config, &mut diff, false);
            adjust_slow_attack_window(&mut next, config, &mut diff, false);
            touched_l4 |= adjust_l4_budgets(&mut next, config, &mut diff, false);
            touched_l4 |= adjust_l4_reject_thresholds(&mut next, config, &mut diff, false);
        }
        "budget" => {
            if let Some(segment) = dominant_segment {
                if matches!(segment.scope_type, "route" | "host_route") {
                    adjust_cc_route_thresholds(&mut next, config, &mut diff, true);
                    adjust_cc_delay_ms(&mut next, config, &mut diff, false);
                } else if segment.scope_type == "host" {
                    adjust_cc_host_thresholds(&mut next, config, &mut diff, true);
                    adjust_cc_delay_ms(&mut next, config, &mut diff, false);
                } else {
                    touched_l4 |= adjust_l4_budgets(&mut next, config, &mut diff, true);
                    touched_l4 |= adjust_l4_reject_thresholds(&mut next, config, &mut diff, true);
                }
            } else {
                touched_l4 |= adjust_l4_budgets(&mut next, config, &mut diff, true);
                touched_l4 |= adjust_l4_reject_thresholds(&mut next, config, &mut diff, true);
            }
        }
        "latency" => {
            if let Some(segment) = dominant_segment {
                if matches!(segment.scope_type, "route" | "host_route") {
                    adjust_cc_route_thresholds(&mut next, config, &mut diff, false);
                    adjust_cc_delay_ms(&mut next, config, &mut diff, true);
                } else if segment.scope_type == "host" {
                    adjust_cc_host_thresholds(&mut next, config, &mut diff, false);
                    adjust_cc_delay_ms(&mut next, config, &mut diff, true);
                } else {
                    touched_l4 |= adjust_l4_budgets(&mut next, config, &mut diff, false);
                    touched_l4 |= adjust_l4_reject_thresholds(&mut next, config, &mut diff, false);
                }
            } else {
                touched_l4 |= adjust_l4_budgets(&mut next, config, &mut diff, false);
                touched_l4 |= adjust_l4_reject_thresholds(&mut next, config, &mut diff, false);
            }
        }
        _ => {}
    }

    if diff.is_empty() {
        runtime.controller_state = "stable".to_string();
        return None;
    }

    next.auto_tuning = config.auto_tuning.clone();
    next = next.normalized();

    state.consecutive_handshake_high = 0;
    state.consecutive_identity_high = 0;
    state.consecutive_slow_attack_high = 0;
    state.consecutive_budget_high = 0;
    state.consecutive_latency_high = 0;
    let cooldown_until = Some(now + config.auto_tuning.cooldown_secs as i64);
    state.cooldown_until = cooldown_until;

    runtime.controller_state = "adjusted".to_string();
    runtime.last_adjust_at = Some(now);
    runtime.last_adjust_reason = Some(
        action_context
            .as_ref()
            .map(|context| context.reason_code.clone())
            .unwrap_or_else(|| format!("adjust_for_{}", action)),
    );
    runtime.last_adjust_diff = diff.clone();
    if let Some(context) = action_context.as_ref() {
        runtime.last_adjust_diff.push(context.detail.clone());
    }
    runtime.cooldown_until = cooldown_until;
    arm_effect_evaluation(
        runtime,
        state,
        now,
        runtime
            .last_adjust_reason
            .clone()
            .unwrap_or_else(|| "adjustment".to_string()),
        action_kind_for_adjust_reason(
            runtime
                .last_adjust_reason
                .as_deref()
                .unwrap_or("adjustment"),
        ),
        deltas,
    );

    Some(AutoTuningDecision {
        next_config: next,
        requires_l4_refresh: touched_l4,
    })
}

fn apply_bootstrap_recommendation(
    config: &Config,
    runtime: &mut AutoTuningRuntimeSnapshot,
    state: &mut AutoTuningControllerState,
    now: i64,
) -> Option<AutoTuningDecision> {
    let recommendation = &runtime.recommendation;
    let mut next = config.clone();
    let mut diff = Vec::new();
    let mut touched_l4 = false;

    state.baseline_before_adjust = Some(config.clone());

    if !is_pinned(config, "l7_config.tls_handshake_timeout_ms") {
        let before = next.l7_config.tls_handshake_timeout_ms;
        if before != recommendation.tls_handshake_timeout_ms {
            next.l7_config.tls_handshake_timeout_ms = recommendation.tls_handshake_timeout_ms;
            diff.push(format!(
                "l7_config.tls_handshake_timeout_ms: {} -> {}",
                before, next.l7_config.tls_handshake_timeout_ms
            ));
        }
    }
    touched_l4 |= set_u32_if_unpinned(
        config,
        &mut next,
        "l4_config.behavior_normal_connection_budget_per_minute",
        recommendation.l4_normal_connection_budget_per_minute,
        &mut diff,
    );
    touched_l4 |= set_u32_if_unpinned(
        config,
        &mut next,
        "l4_config.behavior_suspicious_connection_budget_per_minute",
        recommendation.l4_suspicious_connection_budget_per_minute,
        &mut diff,
    );
    touched_l4 |= set_u32_if_unpinned(
        config,
        &mut next,
        "l4_config.behavior_high_risk_connection_budget_per_minute",
        recommendation.l4_high_risk_connection_budget_per_minute,
        &mut diff,
    );
    touched_l4 |= set_u16_if_unpinned(
        config,
        &mut next,
        "l4_config.behavior_reject_threshold_percent",
        recommendation.l4_reject_threshold_percent,
        &mut diff,
    );
    touched_l4 |= set_u16_if_unpinned(
        config,
        &mut next,
        "l4_config.behavior_critical_reject_threshold_percent",
        recommendation.l4_critical_reject_threshold_percent,
        &mut diff,
    );

    if diff.is_empty() {
        state.bootstrap_applied = true;
        return None;
    }

    next.auto_tuning = config.auto_tuning.clone();
    next = next.normalized();

    let cooldown_until = Some(now + config.auto_tuning.cooldown_secs as i64);
    state.cooldown_until = cooldown_until;
    state.bootstrap_applied = true;

    runtime.controller_state = "bootstrap_adjusted".to_string();
    runtime.last_adjust_at = Some(now);
    runtime.last_adjust_reason = Some("bootstrap_recommendation_apply".to_string());
    runtime.last_adjust_diff = diff.clone();
    runtime.cooldown_until = cooldown_until;
    arm_effect_evaluation(
        runtime,
        state,
        now,
        "bootstrap_recommendation_apply".to_string(),
        AutoTuningActionKind::Bootstrap,
        deltas_from_runtime(runtime),
    );

    Some(AutoTuningDecision {
        next_config: next,
        requires_l4_refresh: touched_l4,
    })
}

fn should_tick(config: &Config, state: &mut AutoTuningControllerState, now: i64) -> bool {
    let interval_secs = config.auto_tuning.control_interval_secs.max(1) as i64;
    if let Some(last_tick_at) = state.last_tick_at {
        if now.saturating_sub(last_tick_at) < interval_secs {
            return false;
        }
    }
    state.last_tick_at = Some(now);
    true
}

fn prune_rollback_timestamps(state: &mut AutoTuningControllerState, now: i64) {
    let threshold = now.saturating_sub(24 * 3600);
    state.rollback_timestamps.retain(|ts| *ts >= threshold);
}

fn should_rollback(
    config: &Config,
    state: &AutoTuningControllerState,
    deltas: &MetricDeltas,
) -> bool {
    if state.baseline_before_adjust.is_none() {
        return false;
    }

    if deltas.proxied_requests_delta < 20 {
        return false;
    }

    let global_regression = deltas.handshake_timeout_rate_percent
        > config.auto_tuning.slo.tls_handshake_timeout_rate_percent * 1.8
        || deltas.bucket_reject_rate_percent
            > config.auto_tuning.slo.bucket_reject_rate_percent * 1.8;
    let hotspot_regression = state
        .pending_effect_evaluation
        .as_ref()
        .map(|pending| has_critical_layered_regression(config, &pending.baseline, deltas))
        .unwrap_or(false);

    global_regression || hotspot_regression
}

fn update_consecutive_counters(
    config: &Config,
    state: &mut AutoTuningControllerState,
    deltas: &MetricDeltas,
) {
    let has_volume = deltas.proxied_requests_delta >= 10;
    let hotspot_budget_pressure = has_hotspot_budget_pressure(config, deltas);
    let hotspot_latency_pressure = has_hotspot_latency_pressure(config, deltas);
    let identity_resolution_pressure = has_identity_resolution_pressure(config, deltas);

    if has_volume
        && deltas.handshake_timeout_rate_percent
            > config.auto_tuning.slo.tls_handshake_timeout_rate_percent
    {
        state.consecutive_handshake_high = state.consecutive_handshake_high.saturating_add(1);
    } else {
        state.consecutive_handshake_high = 0;
    }

    if has_volume && identity_resolution_pressure {
        state.consecutive_identity_high = state.consecutive_identity_high.saturating_add(1);
    } else {
        state.consecutive_identity_high = 0;
    }

    if has_volume
        && (deltas.slow_attack_pressure_percent >= 0.5
            || deltas.direct_idle_no_request_connections >= 2)
    {
        state.consecutive_slow_attack_high = state.consecutive_slow_attack_high.saturating_add(1);
    } else {
        state.consecutive_slow_attack_high = 0;
    }

    if has_volume
        && (deltas.bucket_reject_rate_percent > config.auto_tuning.slo.bucket_reject_rate_percent
            || hotspot_budget_pressure)
    {
        state.consecutive_budget_high = state.consecutive_budget_high.saturating_add(1);
    } else {
        state.consecutive_budget_high = 0;
    }

    if deltas.proxy_successes_delta >= 10
        && (deltas.avg_proxy_latency_ms > config.auto_tuning.slo.p95_proxy_latency_ms
            || hotspot_latency_pressure)
    {
        state.consecutive_latency_high = state.consecutive_latency_high.saturating_add(1);
    } else {
        state.consecutive_latency_high = 0;
    }
}

fn adjust_l4_budgets(
    next: &mut Config,
    config: &Config,
    diff: &mut Vec<String>,
    increase: bool,
) -> bool {
    let mut touched = false;

    touched |= adjust_u32_field(
        config,
        next,
        "l4_config.behavior_normal_connection_budget_per_minute",
        diff,
        increase,
        16,
        10_000,
    );
    touched |= adjust_u32_field(
        config,
        next,
        "l4_config.behavior_suspicious_connection_budget_per_minute",
        diff,
        increase,
        8,
        10_000,
    );
    touched |= adjust_u32_field(
        config,
        next,
        "l4_config.behavior_high_risk_connection_budget_per_minute",
        diff,
        increase,
        4,
        10_000,
    );

    touched
}

fn adjust_l4_reject_thresholds(
    next: &mut Config,
    config: &Config,
    diff: &mut Vec<String>,
    increase: bool,
) -> bool {
    let mut touched = false;

    touched |= adjust_u16_field(
        config,
        next,
        "l4_config.behavior_reject_threshold_percent",
        diff,
        increase,
        100,
        1_000,
    );
    touched |= adjust_u16_field(
        config,
        next,
        "l4_config.behavior_critical_reject_threshold_percent",
        diff,
        increase,
        100,
        1_000,
    );

    touched
}

fn adjust_cc_route_thresholds(
    next: &mut Config,
    config: &Config,
    diff: &mut Vec<String>,
    increase: bool,
) {
    adjust_cc_u32_field(
        config,
        next,
        "l7_config.cc_defense.route_challenge_threshold",
        diff,
        increase,
        3,
        10_000,
    );
    adjust_cc_u32_field(
        config,
        next,
        "l7_config.cc_defense.route_block_threshold",
        diff,
        increase,
        3,
        10_000,
    );
}

fn adjust_cc_host_thresholds(
    next: &mut Config,
    config: &Config,
    diff: &mut Vec<String>,
    increase: bool,
) {
    adjust_cc_u32_field(
        config,
        next,
        "l7_config.cc_defense.host_challenge_threshold",
        diff,
        increase,
        5,
        10_000,
    );
    adjust_cc_u32_field(
        config,
        next,
        "l7_config.cc_defense.host_block_threshold",
        diff,
        increase,
        5,
        10_000,
    );
}

fn adjust_cc_ip_thresholds(
    next: &mut Config,
    config: &Config,
    diff: &mut Vec<String>,
    increase: bool,
) {
    adjust_cc_u32_field(
        config,
        next,
        "l7_config.cc_defense.ip_challenge_threshold",
        diff,
        increase,
        8,
        10_000,
    );
    adjust_cc_u32_field(
        config,
        next,
        "l7_config.cc_defense.ip_block_threshold",
        diff,
        increase,
        12,
        10_000,
    );
}

fn adjust_cc_delay_ms(next: &mut Config, config: &Config, diff: &mut Vec<String>, increase: bool) {
    if is_pinned(config, "l7_config.cc_defense.delay_ms") {
        return;
    }
    let before = next.l7_config.cc_defense.delay_ms;
    let after = adjust_u64(
        before,
        config.auto_tuning.max_step_percent,
        increase,
        10,
        5_000,
    );
    if before == after {
        return;
    }
    next.l7_config.cc_defense.delay_ms = after;
    diff.push(format!(
        "l7_config.cc_defense.delay_ms: {} -> {}",
        before, after
    ));
}

fn adjust_tls_handshake_timeout_ms(
    next: &mut Config,
    config: &Config,
    diff: &mut Vec<String>,
    increase: bool,
) {
    if is_pinned(config, "l7_config.tls_handshake_timeout_ms") {
        return;
    }
    let before = next.l7_config.tls_handshake_timeout_ms;
    let after = adjust_u64(
        before,
        config.auto_tuning.max_step_percent,
        increase,
        500,
        60_000,
    );
    if before == after {
        return;
    }
    next.l7_config.tls_handshake_timeout_ms = after;
    diff.push(format!(
        "l7_config.tls_handshake_timeout_ms: {} -> {}",
        before, after
    ));
}

fn adjust_slow_attack_window(
    next: &mut Config,
    config: &Config,
    diff: &mut Vec<String>,
    increase: bool,
) {
    if !is_pinned(
        config,
        "l7_config.slow_attack_defense.max_events_per_window",
    ) {
        let before = next.l7_config.slow_attack_defense.max_events_per_window;
        let after = adjust_u32(
            before,
            config.auto_tuning.max_step_percent,
            increase,
            1,
            1_000,
        );
        if before != after {
            next.l7_config.slow_attack_defense.max_events_per_window = after;
            diff.push(format!(
                "l7_config.slow_attack_defense.max_events_per_window: {} -> {}",
                before, after
            ));
        }
    }

    if is_pinned(config, "l7_config.slow_attack_defense.event_window_secs") {
        return;
    }
    let before = next.l7_config.slow_attack_defense.event_window_secs;
    let after = adjust_u64(
        before,
        config.auto_tuning.max_step_percent,
        increase,
        30,
        86_400,
    );
    if before == after {
        return;
    }
    next.l7_config.slow_attack_defense.event_window_secs = after;
    diff.push(format!(
        "l7_config.slow_attack_defense.event_window_secs: {} -> {}",
        before, after
    ));
}

fn adjust_u32_field(
    config: &Config,
    next: &mut Config,
    field: &str,
    diff: &mut Vec<String>,
    increase: bool,
    min: u32,
    max: u32,
) -> bool {
    if is_pinned(config, field) {
        return false;
    }

    let before = match field {
        "l4_config.behavior_normal_connection_budget_per_minute" => {
            next.l4_config.behavior_normal_connection_budget_per_minute
        }
        "l4_config.behavior_suspicious_connection_budget_per_minute" => {
            next.l4_config
                .behavior_suspicious_connection_budget_per_minute
        }
        "l4_config.behavior_high_risk_connection_budget_per_minute" => {
            next.l4_config
                .behavior_high_risk_connection_budget_per_minute
        }
        _ => return false,
    };

    let after = adjust_u32(
        before,
        config.auto_tuning.max_step_percent,
        increase,
        min,
        max,
    );
    if before == after {
        return false;
    }

    match field {
        "l4_config.behavior_normal_connection_budget_per_minute" => {
            next.l4_config.behavior_normal_connection_budget_per_minute = after;
        }
        "l4_config.behavior_suspicious_connection_budget_per_minute" => {
            next.l4_config
                .behavior_suspicious_connection_budget_per_minute = after;
        }
        "l4_config.behavior_high_risk_connection_budget_per_minute" => {
            next.l4_config
                .behavior_high_risk_connection_budget_per_minute = after;
        }
        _ => return false,
    }

    diff.push(format!("{}: {} -> {}", field, before, after));
    true
}

fn adjust_cc_u32_field(
    config: &Config,
    next: &mut Config,
    field: &str,
    diff: &mut Vec<String>,
    increase: bool,
    min: u32,
    max: u32,
) -> bool {
    if is_pinned(config, field) {
        return false;
    }

    let before = match field {
        "l7_config.cc_defense.route_challenge_threshold" => {
            next.l7_config.cc_defense.route_challenge_threshold
        }
        "l7_config.cc_defense.route_block_threshold" => {
            next.l7_config.cc_defense.route_block_threshold
        }
        "l7_config.cc_defense.host_challenge_threshold" => {
            next.l7_config.cc_defense.host_challenge_threshold
        }
        "l7_config.cc_defense.host_block_threshold" => {
            next.l7_config.cc_defense.host_block_threshold
        }
        "l7_config.cc_defense.ip_challenge_threshold" => {
            next.l7_config.cc_defense.ip_challenge_threshold
        }
        "l7_config.cc_defense.ip_block_threshold" => next.l7_config.cc_defense.ip_block_threshold,
        _ => return false,
    };

    let after = adjust_u32(
        before,
        config.auto_tuning.max_step_percent,
        increase,
        min,
        max,
    );
    if before == after {
        return false;
    }

    match field {
        "l7_config.cc_defense.route_challenge_threshold" => {
            next.l7_config.cc_defense.route_challenge_threshold = after
        }
        "l7_config.cc_defense.route_block_threshold" => {
            next.l7_config.cc_defense.route_block_threshold = after
        }
        "l7_config.cc_defense.host_challenge_threshold" => {
            next.l7_config.cc_defense.host_challenge_threshold = after
        }
        "l7_config.cc_defense.host_block_threshold" => {
            next.l7_config.cc_defense.host_block_threshold = after
        }
        "l7_config.cc_defense.ip_challenge_threshold" => {
            next.l7_config.cc_defense.ip_challenge_threshold = after
        }
        "l7_config.cc_defense.ip_block_threshold" => {
            next.l7_config.cc_defense.ip_block_threshold = after
        }
        _ => return false,
    }

    diff.push(format!("{}: {} -> {}", field, before, after));
    true
}

fn adjust_u16_field(
    config: &Config,
    next: &mut Config,
    field: &str,
    diff: &mut Vec<String>,
    increase: bool,
    min: u16,
    max: u16,
) -> bool {
    if is_pinned(config, field) {
        return false;
    }

    let before = match field {
        "l4_config.behavior_reject_threshold_percent" => {
            next.l4_config.behavior_reject_threshold_percent
        }
        "l4_config.behavior_critical_reject_threshold_percent" => {
            next.l4_config.behavior_critical_reject_threshold_percent
        }
        _ => return false,
    };

    let after = adjust_u16(
        before,
        config.auto_tuning.max_step_percent,
        increase,
        min,
        max,
    );
    if before == after {
        return false;
    }

    match field {
        "l4_config.behavior_reject_threshold_percent" => {
            next.l4_config.behavior_reject_threshold_percent = after;
        }
        "l4_config.behavior_critical_reject_threshold_percent" => {
            next.l4_config.behavior_critical_reject_threshold_percent = after;
        }
        _ => return false,
    }

    diff.push(format!("{}: {} -> {}", field, before, after));
    true
}

fn set_u32_if_unpinned(
    config: &Config,
    next: &mut Config,
    field: &str,
    value: u32,
    diff: &mut Vec<String>,
) -> bool {
    if is_pinned(config, field) {
        return false;
    }

    let before = match field {
        "l4_config.behavior_normal_connection_budget_per_minute" => {
            next.l4_config.behavior_normal_connection_budget_per_minute
        }
        "l4_config.behavior_suspicious_connection_budget_per_minute" => {
            next.l4_config
                .behavior_suspicious_connection_budget_per_minute
        }
        "l4_config.behavior_high_risk_connection_budget_per_minute" => {
            next.l4_config
                .behavior_high_risk_connection_budget_per_minute
        }
        _ => return false,
    };

    if before == value {
        return false;
    }

    match field {
        "l4_config.behavior_normal_connection_budget_per_minute" => {
            next.l4_config.behavior_normal_connection_budget_per_minute = value
        }
        "l4_config.behavior_suspicious_connection_budget_per_minute" => {
            next.l4_config
                .behavior_suspicious_connection_budget_per_minute = value
        }
        "l4_config.behavior_high_risk_connection_budget_per_minute" => {
            next.l4_config
                .behavior_high_risk_connection_budget_per_minute = value
        }
        _ => return false,
    }

    diff.push(format!("{}: {} -> {}", field, before, value));
    true
}

fn set_u16_if_unpinned(
    config: &Config,
    next: &mut Config,
    field: &str,
    value: u16,
    diff: &mut Vec<String>,
) -> bool {
    if is_pinned(config, field) {
        return false;
    }

    let before = match field {
        "l4_config.behavior_reject_threshold_percent" => {
            next.l4_config.behavior_reject_threshold_percent
        }
        "l4_config.behavior_critical_reject_threshold_percent" => {
            next.l4_config.behavior_critical_reject_threshold_percent
        }
        _ => return false,
    };

    if before == value {
        return false;
    }

    match field {
        "l4_config.behavior_reject_threshold_percent" => {
            next.l4_config.behavior_reject_threshold_percent = value
        }
        "l4_config.behavior_critical_reject_threshold_percent" => {
            next.l4_config.behavior_critical_reject_threshold_percent = value
        }
        _ => return false,
    }

    diff.push(format!("{}: {} -> {}", field, before, value));
    true
}

fn compute_deltas(previous: &MetricsSnapshot, current: &MetricsSnapshot) -> MetricDeltas {
    let proxied_requests_delta = current
        .proxied_requests
        .saturating_sub(previous.proxied_requests);
    let proxy_successes_delta = current
        .proxy_successes
        .saturating_sub(previous.proxy_successes);
    let tls_handshake_timeouts_delta = current
        .tls_handshake_timeouts
        .saturating_sub(previous.tls_handshake_timeouts);
    let l4_bucket_budget_rejections_delta = current
        .l4_bucket_budget_rejections
        .saturating_sub(previous.l4_bucket_budget_rejections);
    let proxy_latency_micros_total_delta = current
        .proxy_latency_micros_total
        .saturating_sub(previous.proxy_latency_micros_total);
    let trusted_proxy_permit_drops_delta = current
        .trusted_proxy_permit_drops
        .saturating_sub(previous.trusted_proxy_permit_drops);
    let trusted_proxy_l4_degrade_actions_delta = current
        .trusted_proxy_l4_degrade_actions
        .saturating_sub(previous.trusted_proxy_l4_degrade_actions);
    let l7_cc_unresolved_identity_delays_delta = current
        .l7_cc_unresolved_identity_delays
        .saturating_sub(previous.l7_cc_unresolved_identity_delays);
    let l7_friction_events_delta = current
        .l7_cc_challenges
        .saturating_sub(previous.l7_cc_challenges)
        .saturating_add(current.l7_cc_blocks.saturating_sub(previous.l7_cc_blocks))
        .saturating_add(current.l7_cc_delays.saturating_sub(previous.l7_cc_delays))
        .saturating_add(
            current
                .l7_behavior_challenges
                .saturating_sub(previous.l7_behavior_challenges),
        )
        .saturating_add(
            current
                .l7_behavior_blocks
                .saturating_sub(previous.l7_behavior_blocks),
        )
        .saturating_add(
            current
                .l7_behavior_delays
                .saturating_sub(previous.l7_behavior_delays),
        );
    let slow_attack_events_delta = current
        .slow_attack_idle_timeouts
        .saturating_sub(previous.slow_attack_idle_timeouts)
        .saturating_add(
            current
                .slow_attack_header_timeouts
                .saturating_sub(previous.slow_attack_header_timeouts),
        )
        .saturating_add(
            current
                .slow_attack_body_timeouts
                .saturating_sub(previous.slow_attack_body_timeouts),
        )
        .saturating_add(
            current
                .slow_attack_tls_handshake_hits
                .saturating_sub(previous.slow_attack_tls_handshake_hits),
        )
        .saturating_add(
            current
                .slow_attack_blocks
                .saturating_sub(previous.slow_attack_blocks),
        );

    let denominator = proxied_requests_delta.max(1) as f64;
    let handshake_timeout_rate_percent =
        (tls_handshake_timeouts_delta as f64 * 100.0) / denominator;
    let bucket_reject_rate_percent =
        (l4_bucket_budget_rejections_delta as f64 * 100.0) / denominator;
    let avg_proxy_latency_ms = if proxy_successes_delta > 0 {
        ((proxy_latency_micros_total_delta / proxy_successes_delta) / 1000).max(1)
    } else {
        (current.average_proxy_latency_micros / 1000).max(1)
    };
    let identity_resolution_pressure_percent = ((trusted_proxy_permit_drops_delta
        + trusted_proxy_l4_degrade_actions_delta
        + l7_cc_unresolved_identity_delays_delta)
        as f64
        * 100.0)
        / denominator;
    let l7_friction_pressure_percent = (l7_friction_events_delta as f64 * 100.0) / denominator;
    let slow_attack_pressure_percent = (slow_attack_events_delta as f64 * 100.0) / denominator;

    MetricDeltas {
        proxied_requests_delta,
        proxy_successes_delta,
        handshake_timeout_rate_percent,
        bucket_reject_rate_percent,
        avg_proxy_latency_ms,
        identity_resolution_pressure_percent,
        l7_friction_pressure_percent,
        slow_attack_pressure_percent,
        direct_idle_no_request_connections: current.l4_direct_idle_no_request_connections,
        segments: collect_segment_deltas(previous, current),
    }
}

fn compute_request_kind_segment_delta(
    request_kind: &str,
    previous: &ProxyTrafficMetricsSnapshot,
    current: &ProxyTrafficMetricsSnapshot,
) -> TrafficSegmentDelta {
    let proxied_requests_delta = current
        .proxied_requests
        .saturating_sub(previous.proxied_requests);
    let proxy_failures_delta = current
        .proxy_failures
        .saturating_sub(previous.proxy_failures);
    TrafficSegmentDelta {
        scope_type: "request_kind",
        scope_key: request_kind.to_string(),
        host: None,
        route: None,
        request_kind: request_kind.to_string(),
        proxied_requests_delta,
        avg_proxy_latency_ms: (current.average_proxy_latency_micros / 1000).max(1),
        failure_rate_percent: if proxied_requests_delta == 0 {
            0.0
        } else {
            proxy_failures_delta as f64 * 100.0 / proxied_requests_delta as f64
        },
    }
}

fn maybe_finalize_effect_evaluation(
    config: &Config,
    runtime: &mut AutoTuningRuntimeSnapshot,
    state: &mut AutoTuningControllerState,
    deltas: &MetricDeltas,
    now: i64,
) {
    let Some(pending) = state.pending_effect_evaluation.clone() else {
        return;
    };

    let min_sample_requests = 20;
    let deadline_reached = state
        .cooldown_until
        .map(|until| now >= until)
        .unwrap_or(false)
        || now.saturating_sub(pending.adjust_at)
            >= (config.auto_tuning.control_interval_secs.max(1) as i64).saturating_mul(3);

    if deltas.proxied_requests_delta < min_sample_requests && !deadline_reached {
        runtime.last_effect_evaluation = Some(AutoTuningEffectEvaluationSnapshot {
            status: "pending".to_string(),
            observed_at: None,
            sample_requests: deltas.proxied_requests_delta,
            handshake_timeout_rate_delta_percent: 0.0,
            bucket_reject_rate_delta_percent: 0.0,
            avg_proxy_latency_delta_ms: 0,
            segments: Vec::new(),
            summary: format!(
                "waiting for more post-adjust traffic after {}",
                pending.reason
            ),
        });
        return;
    }

    if deltas.proxied_requests_delta < min_sample_requests {
        runtime.last_effect_evaluation = Some(AutoTuningEffectEvaluationSnapshot {
            status: "inconclusive".to_string(),
            observed_at: Some(now),
            sample_requests: deltas.proxied_requests_delta,
            handshake_timeout_rate_delta_percent: 0.0,
            bucket_reject_rate_delta_percent: 0.0,
            avg_proxy_latency_delta_ms: 0,
            segments: Vec::new(),
            summary: format!(
                "insufficient post-adjust traffic to evaluate {}",
                pending.reason
            ),
        });
        state.pending_effect_evaluation = None;
        return;
    }

    let evaluation = evaluate_effect_against_baseline(&pending, deltas, now);
    runtime.last_effect_evaluation = Some(evaluation);
    state.pending_effect_evaluation = None;
}

fn evaluate_effect_against_baseline(
    pending: &PendingEffectEvaluation,
    current: &MetricDeltas,
    now: i64,
) -> AutoTuningEffectEvaluationSnapshot {
    let handshake_delta =
        current.handshake_timeout_rate_percent - pending.baseline.handshake_timeout_rate_percent;
    let bucket_delta =
        current.bucket_reject_rate_percent - pending.baseline.bucket_reject_rate_percent;
    let latency_delta =
        current.avg_proxy_latency_ms as i64 - pending.baseline.avg_proxy_latency_ms as i64;
    let segments = evaluate_segments_against_baseline(current, &pending.baseline);
    let layered_regression = segments.iter().any(|segment| {
        segment.status == "regressed"
            && matches!(segment.scope_type.as_str(), "host" | "route" | "host_route")
    });
    let layered_improvement = segments.iter().any(|segment| segment.status == "improved");

    let score = match pending.action_kind {
        AutoTuningActionKind::Handshake => {
            score_percent_delta(
                handshake_delta,
                tolerance_percent(pending.baseline.handshake_timeout_rate_percent, 0.05),
            ) * 2
                + score_percent_delta(
                    bucket_delta,
                    tolerance_percent(pending.baseline.bucket_reject_rate_percent, 0.05),
                )
                + score_latency_delta(latency_delta)
        }
        AutoTuningActionKind::Identity => {
            score_percent_delta(
                current.identity_resolution_pressure_percent
                    - pending.baseline.identity_resolution_pressure_percent,
                tolerance_percent(pending.baseline.identity_resolution_pressure_percent, 0.25),
            ) * 2
                + score_percent_delta(
                    current.l7_friction_pressure_percent
                        - pending.baseline.l7_friction_pressure_percent,
                    tolerance_percent(pending.baseline.l7_friction_pressure_percent, 0.5),
                )
                + score_percent_delta(
                    current.slow_attack_pressure_percent
                        - pending.baseline.slow_attack_pressure_percent,
                    tolerance_percent(pending.baseline.slow_attack_pressure_percent, 0.1),
                )
                + score_latency_delta(latency_delta)
        }
        AutoTuningActionKind::SlowAttack => {
            score_percent_delta(
                current.slow_attack_pressure_percent
                    - pending.baseline.slow_attack_pressure_percent,
                tolerance_percent(pending.baseline.slow_attack_pressure_percent, 0.1),
            ) * 2
                + score_u64_delta(
                    current.direct_idle_no_request_connections as i64
                        - pending.baseline.direct_idle_no_request_connections as i64,
                    1,
                )
                + score_percent_delta(
                    handshake_delta,
                    tolerance_percent(pending.baseline.handshake_timeout_rate_percent, 0.05),
                )
                + score_percent_delta(
                    bucket_delta,
                    tolerance_percent(pending.baseline.bucket_reject_rate_percent, 0.05),
                )
        }
        AutoTuningActionKind::Budget => {
            score_percent_delta(
                bucket_delta,
                tolerance_percent(pending.baseline.bucket_reject_rate_percent, 0.05),
            ) * 2
                + score_percent_delta(
                    handshake_delta,
                    tolerance_percent(pending.baseline.handshake_timeout_rate_percent, 0.05),
                )
                + score_latency_delta(latency_delta)
        }
        AutoTuningActionKind::Latency => {
            score_latency_delta(latency_delta) * 2
                + score_percent_delta(
                    handshake_delta,
                    tolerance_percent(pending.baseline.handshake_timeout_rate_percent, 0.05),
                )
                + score_percent_delta(
                    bucket_delta,
                    tolerance_percent(pending.baseline.bucket_reject_rate_percent, 0.05),
                )
        }
        AutoTuningActionKind::Bootstrap => {
            score_percent_delta(
                handshake_delta,
                tolerance_percent(pending.baseline.handshake_timeout_rate_percent, 0.05),
            ) + score_percent_delta(
                bucket_delta,
                tolerance_percent(pending.baseline.bucket_reject_rate_percent, 0.05),
            ) + score_latency_delta(latency_delta)
        }
    };

    let focus = action_kind_label(pending.action_kind);
    let status = if score <= -2 || layered_regression {
        "regressed"
    } else if score >= 2 && !layered_regression {
        "improved"
    } else if layered_improvement {
        "mixed"
    } else {
        "mixed"
    };

    AutoTuningEffectEvaluationSnapshot {
        status: status.to_string(),
        observed_at: Some(now),
        sample_requests: current.proxied_requests_delta,
        handshake_timeout_rate_delta_percent: handshake_delta,
        bucket_reject_rate_delta_percent: bucket_delta,
        avg_proxy_latency_delta_ms: latency_delta,
        segments,
        summary: format!(
            "{} after {} with {} focus (handshake {:+.2}pp, bucket {:+.2}pp, latency {:+}ms)",
            status, pending.reason, focus, handshake_delta, bucket_delta, latency_delta
        ),
    }
}

fn score_percent_delta(delta: f64, tolerance: f64) -> i8 {
    if delta <= -tolerance {
        1
    } else if delta >= tolerance {
        -1
    } else {
        0
    }
}

fn score_latency_delta(delta_ms: i64) -> i8 {
    if delta_ms <= -50 {
        1
    } else if delta_ms >= 100 {
        -1
    } else {
        0
    }
}

fn score_u64_delta(delta: i64, tolerance: i64) -> i8 {
    if delta <= -tolerance {
        1
    } else if delta >= tolerance {
        -1
    } else {
        0
    }
}

fn tolerance_percent(baseline: f64, minimum: f64) -> f64 {
    (baseline.abs() * 0.1).max(minimum)
}

fn arm_effect_evaluation(
    runtime: &mut AutoTuningRuntimeSnapshot,
    state: &mut AutoTuningControllerState,
    now: i64,
    reason: String,
    action_kind: AutoTuningActionKind,
    baseline: MetricDeltas,
) {
    state.pending_effect_evaluation = Some(PendingEffectEvaluation {
        adjust_at: now,
        reason: reason.clone(),
        action_kind,
        baseline,
    });
    runtime.last_effect_evaluation = Some(AutoTuningEffectEvaluationSnapshot {
        status: "pending".to_string(),
        observed_at: None,
        sample_requests: 0,
        handshake_timeout_rate_delta_percent: 0.0,
        bucket_reject_rate_delta_percent: 0.0,
        avg_proxy_latency_delta_ms: 0,
        segments: Vec::new(),
        summary: format!("waiting to evaluate {}", reason),
    });
}

fn action_kind_for_adjust_reason(reason: &str) -> AutoTuningActionKind {
    if reason.starts_with("adjust_for_handshake") {
        AutoTuningActionKind::Handshake
    } else if reason.starts_with("adjust_for_identity") {
        AutoTuningActionKind::Identity
    } else if reason.starts_with("adjust_for_slow_attack") {
        AutoTuningActionKind::SlowAttack
    } else if reason.starts_with("adjust_for_budget") {
        AutoTuningActionKind::Budget
    } else if reason.starts_with("adjust_for_latency") {
        AutoTuningActionKind::Latency
    } else if reason == "bootstrap_recommendation_apply" {
        AutoTuningActionKind::Bootstrap
    } else {
        AutoTuningActionKind::Bootstrap
    }
}

fn action_kind_label(action: AutoTuningActionKind) -> &'static str {
    match action {
        AutoTuningActionKind::Bootstrap => "bootstrap",
        AutoTuningActionKind::Handshake => "handshake",
        AutoTuningActionKind::Identity => "identity",
        AutoTuningActionKind::SlowAttack => "slow_attack",
        AutoTuningActionKind::Budget => "budget",
        AutoTuningActionKind::Latency => "latency",
    }
}

fn deltas_from_runtime(runtime: &AutoTuningRuntimeSnapshot) -> MetricDeltas {
    MetricDeltas {
        proxied_requests_delta: 0,
        proxy_successes_delta: 0,
        handshake_timeout_rate_percent: runtime.last_observed_tls_handshake_timeout_rate_percent,
        bucket_reject_rate_percent: runtime.last_observed_bucket_reject_rate_percent,
        avg_proxy_latency_ms: runtime.last_observed_avg_proxy_latency_ms,
        identity_resolution_pressure_percent: runtime
            .last_observed_identity_resolution_pressure_percent,
        l7_friction_pressure_percent: runtime.last_observed_l7_friction_pressure_percent,
        slow_attack_pressure_percent: runtime.last_observed_slow_attack_pressure_percent,
        direct_idle_no_request_connections: runtime
            .last_observed_direct_idle_no_request_connections,
        segments: Vec::new(),
    }
}

fn rollback_effect_snapshot(
    state: &mut AutoTuningControllerState,
    deltas: &MetricDeltas,
    now: i64,
) -> AutoTuningEffectEvaluationSnapshot {
    let summary = state
        .pending_effect_evaluation
        .as_ref()
        .map(|pending| format!("rollback triggered after {}", pending.reason))
        .unwrap_or_else(|| "rollback triggered after prior adjustment".to_string());
    state.pending_effect_evaluation = None;
    AutoTuningEffectEvaluationSnapshot {
        status: "regressed".to_string(),
        observed_at: Some(now),
        sample_requests: deltas.proxied_requests_delta,
        handshake_timeout_rate_delta_percent: 0.0,
        bucket_reject_rate_delta_percent: 0.0,
        avg_proxy_latency_delta_ms: 0,
        segments: Vec::new(),
        summary,
    }
}

fn collect_segment_deltas(
    previous: &MetricsSnapshot,
    current: &MetricsSnapshot,
) -> Vec<TrafficSegmentDelta> {
    let mut segments = vec![
        compute_request_kind_segment_delta(
            "document",
            &previous.document_proxy,
            &current.document_proxy,
        ),
        compute_request_kind_segment_delta("api", &previous.api_proxy, &current.api_proxy),
        compute_request_kind_segment_delta("static", &previous.static_proxy, &current.static_proxy),
        compute_request_kind_segment_delta("other", &previous.other_proxy, &current.other_proxy),
    ];
    segments.extend(collect_top_segment_deltas(
        "host",
        &previous.top_host_segments,
        &current.top_host_segments,
    ));
    segments.extend(collect_top_segment_deltas(
        "route",
        &previous.top_route_segments,
        &current.top_route_segments,
    ));
    segments.extend(collect_top_segment_deltas(
        "host_route",
        &previous.top_host_route_segments,
        &current.top_host_route_segments,
    ));
    segments
}

fn collect_top_segment_deltas(
    expected_scope: &'static str,
    previous: &[ProxyTrafficSegmentSnapshot],
    current: &[ProxyTrafficSegmentSnapshot],
) -> Vec<TrafficSegmentDelta> {
    let previous_by_key = previous
        .iter()
        .map(|segment| (segment.scope_key.clone(), segment))
        .collect::<BTreeMap<_, _>>();
    let current_by_key = current
        .iter()
        .map(|segment| (segment.scope_key.clone(), segment))
        .collect::<BTreeMap<_, _>>();
    let mut keys = previous_by_key
        .keys()
        .cloned()
        .chain(current_by_key.keys().cloned())
        .collect::<Vec<_>>();
    keys.sort();
    keys.dedup();

    keys.into_iter()
        .filter_map(|key| {
            let current_segment = current_by_key.get(&key)?;
            let previous_segment = previous_by_key.get(&key).copied();
            let proxied_requests_delta = current_segment.proxied_requests.saturating_sub(
                previous_segment
                    .map(|item| item.proxied_requests)
                    .unwrap_or(0),
            );
            let proxy_failures_delta = current_segment.proxy_failures.saturating_sub(
                previous_segment
                    .map(|item| item.proxy_failures)
                    .unwrap_or(0),
            );
            Some(TrafficSegmentDelta {
                scope_type: expected_scope,
                scope_key: current_segment.scope_key.clone(),
                host: current_segment.host.clone(),
                route: current_segment.route.clone(),
                request_kind: current_segment.request_kind.clone(),
                proxied_requests_delta,
                avg_proxy_latency_ms: (current_segment.average_proxy_latency_micros / 1000).max(1),
                failure_rate_percent: if proxied_requests_delta == 0 {
                    0.0
                } else {
                    proxy_failures_delta as f64 * 100.0 / proxied_requests_delta as f64
                },
            })
        })
        .collect()
}

fn evaluate_segments_against_baseline(
    current: &MetricDeltas,
    baseline: &MetricDeltas,
) -> Vec<AutoTuningEffectSegmentEvaluationSnapshot> {
    let baseline_by_key = baseline
        .segments
        .iter()
        .map(|segment| (segment_key(segment), segment))
        .collect::<BTreeMap<_, _>>();
    let current_by_key = current
        .segments
        .iter()
        .map(|segment| (segment_key(segment), segment))
        .collect::<BTreeMap<_, _>>();
    let mut keys = baseline_by_key
        .keys()
        .cloned()
        .chain(current_by_key.keys().cloned())
        .collect::<Vec<_>>();
    keys.sort();
    keys.dedup();

    let mut segments = keys
        .into_iter()
        .filter_map(|key| {
            let current_segment = current_by_key.get(&key)?;
            let baseline_segment = baseline_by_key.get(&key).copied();
            Some(evaluate_segment_delta(current_segment, baseline_segment))
        })
        .collect::<Vec<_>>();
    segments.sort_by(|left, right| {
        right
            .sample_requests
            .cmp(&left.sample_requests)
            .then(left.scope_type.cmp(&right.scope_type))
            .then(left.scope_key.cmp(&right.scope_key))
    });
    segments.truncate(12);
    segments
}

fn evaluate_segment_delta(
    current: &TrafficSegmentDelta,
    baseline: Option<&TrafficSegmentDelta>,
) -> AutoTuningEffectSegmentEvaluationSnapshot {
    let baseline_latency = baseline
        .map(|segment| segment.avg_proxy_latency_ms)
        .unwrap_or(0);
    let baseline_failure_rate = baseline
        .map(|segment| segment.failure_rate_percent)
        .unwrap_or(0.0);
    let latency_delta = current.avg_proxy_latency_ms as i64 - baseline_latency as i64;
    let failure_rate_delta = current.failure_rate_percent - baseline_failure_rate;
    let status = if current.proxied_requests_delta < 5 {
        "low_sample"
    } else if latency_delta <= -50 && failure_rate_delta <= -1.0 {
        "improved"
    } else if latency_delta >= 100 || failure_rate_delta >= 2.0 {
        "regressed"
    } else {
        "stable"
    };

    AutoTuningEffectSegmentEvaluationSnapshot {
        scope_type: current.scope_type.to_string(),
        scope_key: current.scope_key.clone(),
        host: current.host.clone(),
        route: current.route.clone(),
        request_kind: current.request_kind.clone(),
        sample_requests: current.proxied_requests_delta,
        avg_proxy_latency_delta_ms: latency_delta,
        failure_rate_delta_percent: failure_rate_delta,
        status: status.to_string(),
    }
}

fn segment_key(segment: &TrafficSegmentDelta) -> String {
    format!("{}::{}", segment.scope_type, segment.scope_key)
}

fn has_hotspot_budget_pressure(config: &Config, deltas: &MetricDeltas) -> bool {
    let threshold = (config.auto_tuning.slo.bucket_reject_rate_percent * 2.0).max(5.0);
    deltas.segments.iter().any(|segment| {
        is_business_layer_segment(segment)
            && segment.proxied_requests_delta >= 8
            && segment.failure_rate_percent >= threshold
    })
}

fn has_identity_resolution_pressure(config: &Config, deltas: &MetricDeltas) -> bool {
    deltas.identity_resolution_pressure_percent
        >= (config.auto_tuning.slo.bucket_reject_rate_percent * 0.75).max(1.0)
        || deltas.l7_friction_pressure_percent
            >= (config.auto_tuning.slo.bucket_reject_rate_percent * 2.0).max(8.0)
        || deltas.slow_attack_pressure_percent >= 0.5
        || deltas.direct_idle_no_request_connections >= 2
}

fn has_hotspot_latency_pressure(config: &Config, deltas: &MetricDeltas) -> bool {
    let threshold = ((config.auto_tuning.slo.p95_proxy_latency_ms as f64) * 1.25)
        .round()
        .max((config.auto_tuning.slo.p95_proxy_latency_ms + 50) as f64) as u64;
    deltas.segments.iter().any(|segment| {
        is_business_layer_segment(segment)
            && segment.proxied_requests_delta >= 8
            && segment.avg_proxy_latency_ms >= threshold
    })
}

fn has_critical_layered_regression(
    config: &Config,
    baseline: &MetricDeltas,
    current: &MetricDeltas,
) -> bool {
    evaluate_segments_against_baseline(current, baseline)
        .into_iter()
        .any(|segment| {
            matches!(segment.scope_type.as_str(), "host" | "route" | "host_route")
                && segment.sample_requests >= 8
                && (segment.status == "regressed"
                    || segment.failure_rate_delta_percent
                        >= (config.auto_tuning.slo.bucket_reject_rate_percent * 1.5).max(3.0)
                    || segment.avg_proxy_latency_delta_ms >= 150)
        })
}

fn is_business_layer_segment(segment: &TrafficSegmentDelta) -> bool {
    matches!(segment.scope_type, "host" | "route" | "host_route")
}

fn action_trigger_context(
    config: &Config,
    action: &str,
    deltas: &MetricDeltas,
    dominant_segment: Option<&TrafficSegmentDelta>,
) -> Option<ActionTriggerContext> {
    match action {
        "handshake" => Some(ActionTriggerContext {
            reason_code: "adjust_for_handshake_global".to_string(),
            detail: format!(
                "triggered by global handshake timeout rate {:.2}% above target {:.2}%",
                deltas.handshake_timeout_rate_percent,
                config.auto_tuning.slo.tls_handshake_timeout_rate_percent
            ),
        }),
        "identity" => Some(ActionTriggerContext {
            reason_code: "adjust_for_identity_resolution_pressure".to_string(),
            detail: format!(
                "triggered by identity pressure {:.2}% with l7 friction {:.2}% and slow-attack {:.2}%",
                deltas.identity_resolution_pressure_percent,
                deltas.l7_friction_pressure_percent,
                deltas.slow_attack_pressure_percent
            ),
        }),
        "slow_attack" => Some(ActionTriggerContext {
            reason_code: "adjust_for_slow_attack_pressure".to_string(),
            detail: format!(
                "triggered by slow-attack {:.2}% with {} idle zero-request direct connections",
                deltas.slow_attack_pressure_percent,
                deltas.direct_idle_no_request_connections
            ),
        }),
        "budget" => dominant_segment.map_or_else(
            || {
                Some(ActionTriggerContext {
                    reason_code: "adjust_for_budget_global".to_string(),
                    detail: format!(
                        "triggered by global bucket reject rate {:.2}% above target {:.2}%",
                        deltas.bucket_reject_rate_percent,
                        config.auto_tuning.slo.bucket_reject_rate_percent
                    ),
                })
            },
            |segment| {
                Some(ActionTriggerContext {
                    reason_code: format!("adjust_for_budget_hot_{}", segment.scope_type),
                    detail: format!(
                        "triggered by hot {} {} failure rate {:.2}% with {} samples",
                        segment.scope_type,
                        segment_descriptor(segment),
                        segment.failure_rate_percent,
                        segment.proxied_requests_delta
                    ),
                })
            },
        ),
        "latency" => dominant_segment.map_or_else(
            || {
                Some(ActionTriggerContext {
                    reason_code: "adjust_for_latency_global".to_string(),
                    detail: format!(
                        "triggered by global proxy latency {}ms above target {}ms",
                        deltas.avg_proxy_latency_ms, config.auto_tuning.slo.p95_proxy_latency_ms
                    ),
                })
            },
            |segment| {
                Some(ActionTriggerContext {
                    reason_code: format!("adjust_for_latency_hot_{}", segment.scope_type),
                    detail: format!(
                        "triggered by hot {} {} latency {}ms with {} samples",
                        segment.scope_type,
                        segment_descriptor(segment),
                        segment.avg_proxy_latency_ms,
                        segment.proxied_requests_delta
                    ),
                })
            },
        ),
        _ => None,
    }
}

fn rollback_trigger_context(
    config: &Config,
    baseline: &MetricDeltas,
    current: &MetricDeltas,
) -> Option<ActionTriggerContext> {
    if let Some(segment) = evaluate_segments_against_baseline(current, baseline)
        .into_iter()
        .find(|segment| {
            matches!(segment.scope_type.as_str(), "host" | "route" | "host_route")
                && segment.sample_requests >= 8
                && (segment.status == "regressed"
                    || segment.failure_rate_delta_percent
                        >= (config.auto_tuning.slo.bucket_reject_rate_percent * 1.5).max(3.0)
                    || segment.avg_proxy_latency_delta_ms >= 150)
        })
    {
        return Some(ActionTriggerContext {
            reason_code: format!("rollback_due_to_hot_{}_regression", segment.scope_type),
            detail: format!(
                "rollback because hot {} {} regressed ({:+}ms, {:+.2}pp, {} samples)",
                segment.scope_type,
                segment.scope_key,
                segment.avg_proxy_latency_delta_ms,
                segment.failure_rate_delta_percent,
                segment.sample_requests
            ),
        });
    }

    if current.handshake_timeout_rate_percent
        > config.auto_tuning.slo.tls_handshake_timeout_rate_percent * 1.8
    {
        return Some(ActionTriggerContext {
            reason_code: "rollback_due_to_handshake_global_regression".to_string(),
            detail: format!(
                "rollback because global handshake timeout rate {:.2}% exceeded {:.2}%",
                current.handshake_timeout_rate_percent,
                config.auto_tuning.slo.tls_handshake_timeout_rate_percent * 1.8
            ),
        });
    }

    if current.bucket_reject_rate_percent > config.auto_tuning.slo.bucket_reject_rate_percent * 1.8
    {
        return Some(ActionTriggerContext {
            reason_code: "rollback_due_to_budget_global_regression".to_string(),
            detail: format!(
                "rollback because global bucket reject rate {:.2}% exceeded {:.2}%",
                current.bucket_reject_rate_percent,
                config.auto_tuning.slo.bucket_reject_rate_percent * 1.8
            ),
        });
    }

    if current.identity_resolution_pressure_percent
        > (baseline.identity_resolution_pressure_percent + 2.0).max(3.0)
    {
        return Some(ActionTriggerContext {
            reason_code: "rollback_due_to_identity_pressure_regression".to_string(),
            detail: format!(
                "rollback because identity pressure rose to {:.2}% from baseline {:.2}%",
                current.identity_resolution_pressure_percent,
                baseline.identity_resolution_pressure_percent
            ),
        });
    }

    None
}

fn dominant_segment_for_action<'a>(
    action: &str,
    deltas: &'a MetricDeltas,
) -> Option<&'a TrafficSegmentDelta> {
    let mut candidates = deltas
        .segments
        .iter()
        .filter(|segment| is_business_layer_segment(segment) && segment.proxied_requests_delta >= 8)
        .collect::<Vec<_>>();
    match action {
        "budget" => candidates.sort_by(|left, right| {
            right
                .failure_rate_percent
                .total_cmp(&left.failure_rate_percent)
                .then(
                    right
                        .proxied_requests_delta
                        .cmp(&left.proxied_requests_delta),
                )
        }),
        "latency" => candidates.sort_by(|left, right| {
            right
                .avg_proxy_latency_ms
                .cmp(&left.avg_proxy_latency_ms)
                .then(
                    right
                        .proxied_requests_delta
                        .cmp(&left.proxied_requests_delta),
                )
        }),
        _ => return None,
    }
    candidates.into_iter().next()
}

fn segment_descriptor(segment: &TrafficSegmentDelta) -> String {
    match segment.scope_type {
        "host" => segment
            .host
            .clone()
            .unwrap_or_else(|| segment.scope_key.clone()),
        "route" => segment
            .route
            .clone()
            .unwrap_or_else(|| segment.scope_key.clone()),
        "host_route" => format!(
            "{} {}",
            segment
                .host
                .clone()
                .unwrap_or_else(|| "unknown-host".to_string()),
            segment
                .route
                .clone()
                .unwrap_or_else(|| "unknown-route".to_string())
        ),
        _ => segment.scope_key.clone(),
    }
}

fn adjust_u64(value: u64, percent: u8, increase: bool, min: u64, max: u64) -> u64 {
    let step = ((value.saturating_mul(percent as u64)) / 100).max(1);
    let next = if increase {
        value.saturating_add(step)
    } else {
        value.saturating_sub(step)
    };
    next.clamp(min, max)
}

fn adjust_u32(value: u32, percent: u8, increase: bool, min: u32, max: u32) -> u32 {
    adjust_u64(value as u64, percent, increase, min as u64, max as u64) as u32
}

fn adjust_u16(value: u16, percent: u8, increase: bool, min: u16, max: u16) -> u16 {
    adjust_u64(value as u64, percent, increase, min as u64, max as u64) as u16
}

fn is_pinned(config: &Config, field: &str) -> bool {
    config
        .auto_tuning
        .pinned_fields
        .iter()
        .any(|item| item.eq_ignore_ascii_case(field))
}

fn recommend(config: &Config, profile: &SystemProfile) -> AutoTuningRecommendationSnapshot {
    let cpu = profile.cpu_cores.max(1) as f64;
    let memory_gb = profile
        .memory_limit_bytes
        .map(|value| value as f64 / (1024.0 * 1024.0 * 1024.0))
        .unwrap_or(2.0)
        .clamp(0.5, 256.0);
    let intent_factor = match config.auto_tuning.intent {
        AutoTuningIntent::Conservative => 0.85,
        AutoTuningIntent::Balanced => 1.0,
        AutoTuningIntent::Aggressive => 1.2,
    };

    let capacity_factor = (cpu * memory_gb.sqrt()).clamp(0.65, 8.0);

    let base_budget = (120.0 * capacity_factor * intent_factor).round() as u32;
    let normal_budget = base_budget.clamp(24, 10_000);
    let suspicious_budget = ((normal_budget as f64) * 0.5).round() as u32;
    let suspicious_budget = suspicious_budget.clamp(8, normal_budget.max(8));
    let high_risk_budget = ((suspicious_budget as f64) * 0.35).round() as u32;
    let high_risk_budget = high_risk_budget.clamp(4, suspicious_budget.max(4));

    let low_capacity_penalty = (1.6 - capacity_factor).max(0.0);
    let intent_timeout_bonus = match config.auto_tuning.intent {
        AutoTuningIntent::Conservative => 350.0,
        AutoTuningIntent::Balanced => 0.0,
        AutoTuningIntent::Aggressive => -150.0,
    };
    let tls_handshake_timeout_ms =
        (3000.0 + low_capacity_penalty * 900.0 + intent_timeout_bonus).round() as u64;
    let tls_handshake_timeout_ms = tls_handshake_timeout_ms.clamp(1500, 15_000);

    let reject_threshold = (330.0 - (capacity_factor * 8.0)
        + match config.auto_tuning.intent {
            AutoTuningIntent::Conservative => 25.0,
            AutoTuningIntent::Balanced => 0.0,
            AutoTuningIntent::Aggressive => -20.0,
        })
    .round() as u16;
    let reject_threshold = reject_threshold.clamp(220, 450);

    let critical_reject_threshold = (220.0 - (capacity_factor * 5.0)
        + match config.auto_tuning.intent {
            AutoTuningIntent::Conservative => 20.0,
            AutoTuningIntent::Balanced => 0.0,
            AutoTuningIntent::Aggressive => -15.0,
        })
    .round() as u16;
    let critical_reject_threshold = critical_reject_threshold.clamp(160, reject_threshold);

    AutoTuningRecommendationSnapshot {
        l4_normal_connection_budget_per_minute: normal_budget,
        l4_suspicious_connection_budget_per_minute: suspicious_budget,
        l4_high_risk_connection_budget_per_minute: high_risk_budget,
        l4_reject_threshold_percent: reject_threshold,
        l4_critical_reject_threshold_percent: critical_reject_threshold,
        tls_handshake_timeout_ms,
    }
}

pub(crate) fn controller_state_label(mode: AutoTuningMode) -> &'static str {
    match mode {
        AutoTuningMode::Off => "disabled",
        AutoTuningMode::Observe => "observe_only",
        AutoTuningMode::Active => "active_bootstrap_pending",
    }
}

#[cfg(test)]
mod tests {
    use crate::config::{AutoTuningIntent, AutoTuningMode, Config};
    use crate::metrics::MetricsSnapshot;

    use super::{recommend, run_control_step, AutoTuningControllerState};
    use crate::core::system_profile::SystemProfile;

    #[test]
    fn recommendation_scales_with_capacity() {
        let mut config = Config::default();
        config.auto_tuning.intent = AutoTuningIntent::Balanced;

        let low = recommend(
            &config,
            &SystemProfile {
                cpu_cores: 1,
                memory_limit_bytes: Some(512 * 1024 * 1024),
            },
        );
        let high = recommend(
            &config,
            &SystemProfile {
                cpu_cores: 8,
                memory_limit_bytes: Some(16 * 1024 * 1024 * 1024),
            },
        );

        assert!(
            high.l4_normal_connection_budget_per_minute
                > low.l4_normal_connection_budget_per_minute
        );
        assert!(high.tls_handshake_timeout_ms <= low.tls_handshake_timeout_ms);
    }

    #[test]
    fn observe_mode_emits_no_decision() {
        let mut config = Config::default();
        config.auto_tuning.mode = AutoTuningMode::Observe;
        let mut runtime = super::build_runtime_snapshot(&config);
        let mut state = AutoTuningControllerState::default();

        let baseline = MetricsSnapshot {
            proxied_requests: 100,
            tls_handshake_timeouts: 0,
            l4_bucket_budget_rejections: 0,
            ..MetricsSnapshot::default()
        };
        let current = MetricsSnapshot {
            proxied_requests: 200,
            tls_handshake_timeouts: 30,
            l4_bucket_budget_rejections: 20,
            ..MetricsSnapshot::default()
        };

        let warmup = run_control_step(&config, &mut runtime, &mut state, &baseline, 100);
        assert!(warmup.is_none());
        let decision = run_control_step(&config, &mut runtime, &mut state, &current, 140);
        assert!(decision.is_none());
    }

    #[test]
    fn identity_pressure_prefers_tightening_l4_and_cc_thresholds() {
        let mut config = Config::default();
        config.auto_tuning.mode = AutoTuningMode::Active;
        config.auto_tuning.runtime_adjust_enabled = true;
        config.auto_tuning.control_interval_secs = 10;
        config.auto_tuning.cooldown_secs = 30;

        let original_l4_budget = config
            .l4_config
            .behavior_normal_connection_budget_per_minute;
        let original_ip_threshold = config.l7_config.cc_defense.ip_challenge_threshold;
        let original_delay_ms = config.l7_config.cc_defense.delay_ms;

        let mut runtime = super::build_runtime_snapshot(&config);
        let mut state = AutoTuningControllerState::default();

        let warmup = MetricsSnapshot {
            proxied_requests: 100,
            proxy_successes: 100,
            proxy_latency_micros_total: 100_000_000,
            ..MetricsSnapshot::default()
        };
        assert!(run_control_step(&config, &mut runtime, &mut state, &warmup, 100).is_none());
        state.bootstrap_applied = true;

        for (index, proxied_requests) in [140_u64, 180, 220].into_iter().enumerate() {
            let metrics = MetricsSnapshot {
                proxied_requests,
                proxy_successes: proxied_requests,
                proxy_latency_micros_total: proxied_requests * 1_000_000,
                trusted_proxy_permit_drops: 2 + index as u64 * 2,
                trusted_proxy_l4_degrade_actions: 2 + index as u64 * 2,
                l7_cc_unresolved_identity_delays: 3 + index as u64 * 3,
                l7_cc_challenges: 6 + index as u64 * 4,
                l7_behavior_delays: 4 + index as u64 * 2,
                ..MetricsSnapshot::default()
            };
            let decision = run_control_step(
                &config,
                &mut runtime,
                &mut state,
                &metrics,
                110 + index as i64 * 10,
            );
            if index < 2 {
                assert!(decision.is_none());
            } else {
                let decision = decision.expect("third identity-pressure window should adjust");
                assert_eq!(
                    runtime.last_adjust_reason.as_deref(),
                    Some("adjust_for_identity_resolution_pressure")
                );
                assert!(
                    decision
                        .next_config
                        .l4_config
                        .behavior_normal_connection_budget_per_minute
                        < original_l4_budget
                );
                assert!(
                    decision
                        .next_config
                        .l7_config
                        .cc_defense
                        .ip_challenge_threshold
                        < original_ip_threshold
                );
                assert!(decision.next_config.l7_config.cc_defense.delay_ms > original_delay_ms);
            }
        }
    }

    #[test]
    fn active_mode_records_effect_evaluation_after_adjustment() {
        let mut config = Config::default();
        config.auto_tuning.mode = AutoTuningMode::Active;
        config.auto_tuning.runtime_adjust_enabled = true;
        config.auto_tuning.control_interval_secs = 10;
        config.auto_tuning.cooldown_secs = 30;

        let mut runtime = super::build_runtime_snapshot(&config);
        let mut state = AutoTuningControllerState::default();

        let warmup = MetricsSnapshot {
            proxied_requests: 100,
            proxy_successes: 100,
            proxy_latency_micros_total: 100_000_000,
            ..MetricsSnapshot::default()
        };
        assert!(run_control_step(&config, &mut runtime, &mut state, &warmup, 100).is_none());
        state.bootstrap_applied = true;

        let baseline = MetricsSnapshot {
            proxied_requests: 140,
            proxy_successes: 140,
            proxy_latency_micros_total: 140_000_000,
            tls_handshake_timeouts: 10,
            ..MetricsSnapshot::default()
        };
        assert!(run_control_step(&config, &mut runtime, &mut state, &baseline, 110).is_none());

        let trigger = MetricsSnapshot {
            proxied_requests: 180,
            proxy_successes: 180,
            proxy_latency_micros_total: 180_000_000,
            tls_handshake_timeouts: 20,
            ..MetricsSnapshot::default()
        };
        assert!(run_control_step(&config, &mut runtime, &mut state, &trigger, 120).is_none());

        let decision_window = MetricsSnapshot {
            proxied_requests: 220,
            proxy_successes: 220,
            proxy_latency_micros_total: 220_000_000,
            tls_handshake_timeouts: 30,
            ..MetricsSnapshot::default()
        };
        let decision = run_control_step(&config, &mut runtime, &mut state, &decision_window, 130);
        assert!(
            decision.is_some(),
            "third consecutive high handshake window should adjust"
        );
        assert_eq!(
            runtime
                .last_effect_evaluation
                .as_ref()
                .map(|value| value.status.as_str()),
            Some("pending")
        );

        let improved = MetricsSnapshot {
            proxied_requests: 1_020,
            proxy_successes: 1_020,
            proxy_latency_micros_total: 1_020_000_000,
            tls_handshake_timeouts: 31,
            ..MetricsSnapshot::default()
        };
        assert!(run_control_step(&config, &mut runtime, &mut state, &improved, 140).is_none());
        assert_eq!(
            runtime
                .last_effect_evaluation
                .as_ref()
                .map(|value| value.status.as_str()),
            Some("improved")
        );
    }

    #[test]
    fn active_mode_rolls_back_on_hot_route_regression() {
        let mut config = Config::default();
        config.auto_tuning.mode = AutoTuningMode::Active;
        config.auto_tuning.runtime_adjust_enabled = true;
        config.auto_tuning.control_interval_secs = 10;
        config.auto_tuning.cooldown_secs = 30;

        let mut runtime = super::build_runtime_snapshot(&config);
        let mut state = AutoTuningControllerState::default();

        let warmup = MetricsSnapshot {
            proxied_requests: 100,
            proxy_successes: 100,
            proxy_latency_micros_total: 100_000_000,
            ..MetricsSnapshot::default()
        };
        assert!(run_control_step(&config, &mut runtime, &mut state, &warmup, 100).is_none());
        state.bootstrap_applied = true;

        let baseline = MetricsSnapshot {
            proxied_requests: 140,
            proxy_successes: 140,
            proxy_latency_micros_total: 140_000_000,
            tls_handshake_timeouts: 10,
            top_route_segments: vec![crate::metrics::ProxyTrafficSegmentSnapshot {
                scope_type: "route".to_string(),
                scope_key: "/checkout|api".to_string(),
                host: None,
                route: Some("/checkout".to_string()),
                request_kind: "api".to_string(),
                proxied_requests: 20,
                proxy_successes: 20,
                proxy_failures: 0,
                average_proxy_latency_micros: 80_000,
            }],
            ..MetricsSnapshot::default()
        };
        assert!(run_control_step(&config, &mut runtime, &mut state, &baseline, 110).is_none());

        let trigger = MetricsSnapshot {
            proxied_requests: 180,
            proxy_successes: 180,
            proxy_latency_micros_total: 180_000_000,
            tls_handshake_timeouts: 20,
            top_route_segments: vec![crate::metrics::ProxyTrafficSegmentSnapshot {
                scope_type: "route".to_string(),
                scope_key: "/checkout|api".to_string(),
                host: None,
                route: Some("/checkout".to_string()),
                request_kind: "api".to_string(),
                proxied_requests: 24,
                proxy_successes: 24,
                proxy_failures: 0,
                average_proxy_latency_micros: 90_000,
            }],
            ..MetricsSnapshot::default()
        };
        assert!(run_control_step(&config, &mut runtime, &mut state, &trigger, 120).is_none());

        let decision_window = MetricsSnapshot {
            proxied_requests: 220,
            proxy_successes: 220,
            proxy_latency_micros_total: 220_000_000,
            tls_handshake_timeouts: 30,
            top_route_segments: vec![crate::metrics::ProxyTrafficSegmentSnapshot {
                scope_type: "route".to_string(),
                scope_key: "/checkout|api".to_string(),
                host: None,
                route: Some("/checkout".to_string()),
                request_kind: "api".to_string(),
                proxied_requests: 28,
                proxy_successes: 28,
                proxy_failures: 0,
                average_proxy_latency_micros: 95_000,
            }],
            ..MetricsSnapshot::default()
        };
        assert!(
            run_control_step(&config, &mut runtime, &mut state, &decision_window, 130).is_some()
        );

        let hotspot_regressed = MetricsSnapshot {
            proxied_requests: 260,
            proxy_successes: 260,
            proxy_latency_micros_total: 260_000_000,
            tls_handshake_timeouts: 31,
            top_route_segments: vec![crate::metrics::ProxyTrafficSegmentSnapshot {
                scope_type: "route".to_string(),
                scope_key: "/checkout|api".to_string(),
                host: None,
                route: Some("/checkout".to_string()),
                request_kind: "api".to_string(),
                proxied_requests: 40,
                proxy_successes: 36,
                proxy_failures: 4,
                average_proxy_latency_micros: 320_000,
            }],
            ..MetricsSnapshot::default()
        };
        let rollback = run_control_step(&config, &mut runtime, &mut state, &hotspot_regressed, 140);
        assert!(
            rollback.is_some(),
            "hot route regression should trigger rollback"
        );
        assert_eq!(runtime.controller_state, "rollback");
    }

    #[test]
    fn hot_route_budget_pressure_prefers_route_threshold_adjustment() {
        let mut config = Config::default();
        config.auto_tuning.mode = AutoTuningMode::Active;
        config.auto_tuning.runtime_adjust_enabled = true;
        config.auto_tuning.control_interval_secs = 10;
        config.auto_tuning.cooldown_secs = 30;

        let original_route_threshold = config.l7_config.cc_defense.route_challenge_threshold;
        let original_l4_budget = config
            .l4_config
            .behavior_normal_connection_budget_per_minute;

        let mut runtime = super::build_runtime_snapshot(&config);
        let mut state = AutoTuningControllerState::default();

        let warmup = MetricsSnapshot {
            proxied_requests: 100,
            proxy_successes: 100,
            proxy_latency_micros_total: 100_000_000,
            ..MetricsSnapshot::default()
        };
        assert!(run_control_step(&config, &mut runtime, &mut state, &warmup, 100).is_none());
        state.bootstrap_applied = true;

        for (index, proxied_requests) in [140_u64, 180, 220].into_iter().enumerate() {
            let metrics = MetricsSnapshot {
                proxied_requests,
                proxy_successes: proxied_requests,
                proxy_latency_micros_total: proxied_requests * 1_000_000,
                top_route_segments: vec![crate::metrics::ProxyTrafficSegmentSnapshot {
                    scope_type: "route".to_string(),
                    scope_key: "/checkout|api".to_string(),
                    host: None,
                    route: Some("/checkout".to_string()),
                    request_kind: "api".to_string(),
                    proxied_requests: 12 + index as u64 * 10,
                    proxy_successes: 8 + index as u64 * 8,
                    proxy_failures: 4 + index as u64 * 2,
                    average_proxy_latency_micros: 110_000,
                }],
                ..MetricsSnapshot::default()
            };
            let decision = run_control_step(
                &config,
                &mut runtime,
                &mut state,
                &metrics,
                110 + index as i64 * 10,
            );
            if index < 2 {
                assert!(decision.is_none());
            } else {
                let decision = decision.expect("third hot-route budget window should adjust");
                assert_eq!(
                    runtime.last_adjust_reason.as_deref(),
                    Some("adjust_for_budget_hot_route")
                );
                assert!(
                    decision
                        .next_config
                        .l7_config
                        .cc_defense
                        .route_challenge_threshold
                        > original_route_threshold
                );
                assert_eq!(
                    decision
                        .next_config
                        .l4_config
                        .behavior_normal_connection_budget_per_minute,
                    original_l4_budget
                );
            }
        }
    }

    #[test]
    fn slow_attack_pressure_prefers_tightening_handshake_and_slow_attack_window() {
        let mut config = Config::default();
        config.auto_tuning.mode = AutoTuningMode::Active;
        config.auto_tuning.runtime_adjust_enabled = true;
        config.auto_tuning.control_interval_secs = 10;
        config.auto_tuning.cooldown_secs = 30;

        let original_handshake_timeout_ms = config.l7_config.tls_handshake_timeout_ms;
        let original_event_window_secs = config.l7_config.slow_attack_defense.event_window_secs;
        let original_max_events = config.l7_config.slow_attack_defense.max_events_per_window;

        let mut runtime = super::build_runtime_snapshot(&config);
        let mut state = AutoTuningControllerState::default();

        let warmup = MetricsSnapshot {
            proxied_requests: 100,
            proxy_successes: 100,
            proxy_latency_micros_total: 100_000_000,
            ..MetricsSnapshot::default()
        };
        assert!(run_control_step(&config, &mut runtime, &mut state, &warmup, 100).is_none());
        state.bootstrap_applied = true;

        for (index, proxied_requests) in [140_u64, 180, 220].into_iter().enumerate() {
            let metrics = MetricsSnapshot {
                proxied_requests,
                proxy_successes: proxied_requests,
                proxy_latency_micros_total: proxied_requests * 1_000_000,
                slow_attack_tls_handshake_hits: 1 + index as u64 * 2,
                slow_attack_blocks: index as u64,
                l4_direct_idle_no_request_connections: 3 + index as u64,
                ..MetricsSnapshot::default()
            };
            let decision = run_control_step(
                &config,
                &mut runtime,
                &mut state,
                &metrics,
                110 + index as i64 * 10,
            );
            if index < 2 {
                assert!(decision.is_none());
            } else {
                let decision = decision.expect("third slow-attack window should adjust");
                assert_eq!(
                    runtime.last_adjust_reason.as_deref(),
                    Some("adjust_for_slow_attack_pressure")
                );
                assert!(
                    decision.next_config.l7_config.tls_handshake_timeout_ms
                        < original_handshake_timeout_ms
                );
                assert!(
                    decision
                        .next_config
                        .l7_config
                        .slow_attack_defense
                        .event_window_secs
                        < original_event_window_secs
                );
                assert!(
                    decision
                        .next_config
                        .l7_config
                        .slow_attack_defense
                        .max_events_per_window
                        <= original_max_events
                );
            }
        }
    }
}
