use crate::config::{AutoTuningIntent, AutoTuningMode, Config};
use crate::metrics::MetricsSnapshot;

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
    pub last_observed_tls_handshake_timeout_rate_percent: f64,
    pub last_observed_bucket_reject_rate_percent: f64,
    pub last_observed_avg_proxy_latency_ms: u64,
    pub recommendation: AutoTuningRecommendationSnapshot,
}

#[derive(Debug, Clone, Default)]
pub struct AutoTuningControllerState {
    pub last_tick_at: Option<i64>,
    pub cooldown_until: Option<i64>,
    pub last_metrics: Option<MetricsSnapshot>,
    pub consecutive_handshake_high: u8,
    pub consecutive_budget_high: u8,
    pub consecutive_latency_high: u8,
    pub baseline_before_adjust: Option<Config>,
    pub rollback_timestamps: Vec<i64>,
    pub bootstrap_applied: bool,
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
        last_observed_tls_handshake_timeout_rate_percent: 0.0,
        last_observed_bucket_reject_rate_percent: 0.0,
        last_observed_avg_proxy_latency_ms: 0,
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

    if matches!(config.auto_tuning.mode, AutoTuningMode::Off) {
        runtime.controller_state = "disabled".to_string();
        state.consecutive_handshake_high = 0;
        state.consecutive_budget_high = 0;
        state.consecutive_latency_high = 0;
        state.baseline_before_adjust = None;
        state.bootstrap_applied = false;
        return None;
    }

    if let Some(cooldown_until) = state.cooldown_until {
        if now < cooldown_until {
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
        runtime.last_adjust_reason = Some("rollback_due_to_metric_regression".to_string());
        runtime.last_adjust_diff = vec!["restored previous stable runtime config".to_string()];
        runtime.cooldown_until = cooldown_until;

        state.consecutive_handshake_high = 0;
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

    if matches!(config.auto_tuning.mode, AutoTuningMode::Observe)
        || !config.auto_tuning.runtime_adjust_enabled
    {
        runtime.controller_state = "observe_pending_adjust".to_string();
        runtime.last_adjust_reason = Some(format!("would_adjust_{}", action));
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
        "budget" => {
            touched_l4 |= adjust_l4_budgets(&mut next, config, &mut diff, true);
            touched_l4 |= adjust_l4_reject_thresholds(&mut next, config, &mut diff, true);
        }
        "latency" => {
            touched_l4 |= adjust_l4_budgets(&mut next, config, &mut diff, false);
            touched_l4 |= adjust_l4_reject_thresholds(&mut next, config, &mut diff, false);
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
    state.consecutive_budget_high = 0;
    state.consecutive_latency_high = 0;
    let cooldown_until = Some(now + config.auto_tuning.cooldown_secs as i64);
    state.cooldown_until = cooldown_until;

    runtime.controller_state = "adjusted".to_string();
    runtime.last_adjust_at = Some(now);
    runtime.last_adjust_reason = Some(format!("adjust_for_{}", action));
    runtime.last_adjust_diff = diff.clone();
    runtime.cooldown_until = cooldown_until;

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

    deltas.handshake_timeout_rate_percent
        > config.auto_tuning.slo.tls_handshake_timeout_rate_percent * 1.8
        || deltas.bucket_reject_rate_percent
            > config.auto_tuning.slo.bucket_reject_rate_percent * 1.8
}

fn update_consecutive_counters(
    config: &Config,
    state: &mut AutoTuningControllerState,
    deltas: &MetricDeltas,
) {
    let has_volume = deltas.proxied_requests_delta >= 10;

    if has_volume
        && deltas.handshake_timeout_rate_percent
            > config.auto_tuning.slo.tls_handshake_timeout_rate_percent
    {
        state.consecutive_handshake_high = state.consecutive_handshake_high.saturating_add(1);
    } else {
        state.consecutive_handshake_high = 0;
    }

    if has_volume
        && deltas.bucket_reject_rate_percent > config.auto_tuning.slo.bucket_reject_rate_percent
    {
        state.consecutive_budget_high = state.consecutive_budget_high.saturating_add(1);
    } else {
        state.consecutive_budget_high = 0;
    }

    if deltas.proxy_successes_delta >= 10
        && deltas.avg_proxy_latency_ms > config.auto_tuning.slo.p95_proxy_latency_ms
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

    MetricDeltas {
        proxied_requests_delta,
        proxy_successes_delta,
        handshake_timeout_rate_percent,
        bucket_reject_rate_percent,
        avg_proxy_latency_ms,
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
}
