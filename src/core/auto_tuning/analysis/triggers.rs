use crate::config::Config;

use super::super::types::*;
use super::effect::evaluate_segments_against_baseline;
use super::pressure::is_business_layer_segment;

pub(in crate::core::auto_tuning) fn action_kind_for_adjust_reason(
    reason: &str,
) -> AutoTuningActionKind {
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

pub(super) fn action_kind_label(action: AutoTuningActionKind) -> &'static str {
    match action {
        AutoTuningActionKind::Bootstrap => "bootstrap",
        AutoTuningActionKind::Handshake => "handshake",
        AutoTuningActionKind::Identity => "identity",
        AutoTuningActionKind::SlowAttack => "slow_attack",
        AutoTuningActionKind::Budget => "budget",
        AutoTuningActionKind::Latency => "latency",
    }
}

pub(in crate::core::auto_tuning) fn action_trigger_context(
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

pub(in crate::core::auto_tuning) fn rollback_trigger_context(
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

pub(in crate::core::auto_tuning) fn dominant_segment_for_action<'a>(
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
