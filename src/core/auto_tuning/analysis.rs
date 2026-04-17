use crate::config::Config;
use crate::metrics::{MetricsSnapshot, ProxyTrafficMetricsSnapshot, ProxyTrafficSegmentSnapshot};
use std::collections::BTreeMap;

use super::types::*;

pub(super) fn compute_deltas(
    previous: &MetricsSnapshot,
    current: &MetricsSnapshot,
) -> MetricDeltas {
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

pub(super) fn maybe_finalize_effect_evaluation(
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

pub(super) fn arm_effect_evaluation(
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

pub(super) fn action_kind_for_adjust_reason(reason: &str) -> AutoTuningActionKind {
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

pub(super) fn deltas_from_runtime(runtime: &AutoTuningRuntimeSnapshot) -> MetricDeltas {
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

pub(super) fn rollback_effect_snapshot(
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

pub(super) fn has_hotspot_budget_pressure(config: &Config, deltas: &MetricDeltas) -> bool {
    let threshold = (config.auto_tuning.slo.bucket_reject_rate_percent * 2.0).max(5.0);
    deltas.segments.iter().any(|segment| {
        is_business_layer_segment(segment)
            && segment.proxied_requests_delta >= 8
            && segment.failure_rate_percent >= threshold
    })
}

pub(super) fn has_identity_resolution_pressure(config: &Config, deltas: &MetricDeltas) -> bool {
    deltas.identity_resolution_pressure_percent
        >= (config.auto_tuning.slo.bucket_reject_rate_percent * 0.75).max(1.0)
        || deltas.l7_friction_pressure_percent
            >= (config.auto_tuning.slo.bucket_reject_rate_percent * 2.0).max(8.0)
        || deltas.slow_attack_pressure_percent >= 0.5
        || deltas.direct_idle_no_request_connections >= 2
}

pub(super) fn has_hotspot_latency_pressure(config: &Config, deltas: &MetricDeltas) -> bool {
    let threshold = ((config.auto_tuning.slo.p95_proxy_latency_ms as f64) * 1.25)
        .round()
        .max((config.auto_tuning.slo.p95_proxy_latency_ms + 50) as f64) as u64;
    deltas.segments.iter().any(|segment| {
        is_business_layer_segment(segment)
            && segment.proxied_requests_delta >= 8
            && segment.avg_proxy_latency_ms >= threshold
    })
}

pub(super) fn has_critical_layered_regression(
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

pub(super) fn action_trigger_context(
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

pub(super) fn rollback_trigger_context(
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

pub(super) fn dominant_segment_for_action<'a>(
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
