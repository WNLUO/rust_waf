use crate::config::{AutoTuningMode, Config};
use crate::metrics::MetricsSnapshot;

use super::system_profile::detect_system_profile;

mod adjustments;
mod analysis;
mod recommendation;
mod types;

use adjustments::{
    adjust_cc_delay_ms, adjust_cc_host_thresholds, adjust_cc_ip_thresholds,
    adjust_cc_route_thresholds, adjust_l4_budgets, adjust_l4_reject_thresholds,
    adjust_slow_attack_window, adjust_tls_handshake_timeout_ms, is_pinned, set_u16_if_unpinned,
    set_u32_if_unpinned,
};
use analysis::{
    action_kind_for_adjust_reason, action_trigger_context, arm_effect_evaluation, compute_deltas,
    deltas_from_runtime, dominant_segment_for_action, has_critical_layered_regression,
    has_hotspot_budget_pressure, has_hotspot_latency_pressure, has_identity_resolution_pressure,
    maybe_finalize_effect_evaluation, rollback_effect_snapshot, rollback_trigger_context,
};
use recommendation::{controller_state_label, recommend};
use types::*;

pub use types::{
    AutoTuningControllerState, AutoTuningRecommendationSnapshot, AutoTuningRuntimeSnapshot,
};

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
        consecutive_handshake_high: 0,
        consecutive_identity_high: 0,
        consecutive_slow_attack_high: 0,
        consecutive_budget_high: 0,
        consecutive_latency_high: 0,
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

fn sync_runtime_signal_windows(
    runtime: &mut AutoTuningRuntimeSnapshot,
    state: &AutoTuningControllerState,
) {
    runtime.consecutive_handshake_high = state.consecutive_handshake_high;
    runtime.consecutive_identity_high = state.consecutive_identity_high;
    runtime.consecutive_slow_attack_high = state.consecutive_slow_attack_high;
    runtime.consecutive_budget_high = state.consecutive_budget_high;
    runtime.consecutive_latency_high = state.consecutive_latency_high;
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
            sync_runtime_signal_windows(runtime, state);
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
        state.consecutive_slow_attack_high = 0;
        state.consecutive_budget_high = 0;
        state.consecutive_latency_high = 0;
        state.baseline_before_adjust = None;
        state.bootstrap_applied = false;
        sync_runtime_signal_windows(runtime, state);
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
                state.consecutive_slow_attack_high = 0;
                state.consecutive_budget_high = 0;
                state.consecutive_latency_high = 0;
                sync_runtime_signal_windows(runtime, state);

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
        sync_runtime_signal_windows(runtime, state);

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
    sync_runtime_signal_windows(runtime, state);

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
            adjust_tls_handshake_timeout_ms(&mut next, config, &mut diff, true);
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
    sync_runtime_signal_windows(runtime, state);
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
        sync_runtime_signal_windows(runtime, state);
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

#[cfg(test)]
mod tests;
