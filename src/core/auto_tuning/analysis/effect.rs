use crate::config::Config;
use std::collections::BTreeMap;

use super::super::types::*;
use super::triggers::action_kind_label;

pub(in crate::core::auto_tuning) fn maybe_finalize_effect_evaluation(
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

pub(in crate::core::auto_tuning) fn arm_effect_evaluation(
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

pub(in crate::core::auto_tuning) fn rollback_effect_snapshot(
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

pub(super) fn evaluate_segments_against_baseline(
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
