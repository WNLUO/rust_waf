use crate::config::Config;

use super::super::types::*;
use super::effect::evaluate_segments_against_baseline;

pub(in crate::core::auto_tuning) fn has_hotspot_budget_pressure(
    config: &Config,
    deltas: &MetricDeltas,
) -> bool {
    let threshold = (config.auto_tuning.slo.bucket_reject_rate_percent * 2.0).max(5.0);
    deltas.segments.iter().any(|segment| {
        is_business_layer_segment(segment)
            && segment.proxied_requests_delta >= 8
            && segment.failure_rate_percent >= threshold
    })
}

pub(in crate::core::auto_tuning) fn has_identity_resolution_pressure(
    config: &Config,
    deltas: &MetricDeltas,
) -> bool {
    deltas.identity_resolution_pressure_percent
        >= (config.auto_tuning.slo.bucket_reject_rate_percent * 0.75).max(1.0)
        || deltas.l7_friction_pressure_percent
            >= (config.auto_tuning.slo.bucket_reject_rate_percent * 2.0).max(8.0)
        || deltas.slow_attack_pressure_percent >= 0.5
        || deltas.direct_idle_no_request_connections >= 2
}

pub(in crate::core::auto_tuning) fn has_hotspot_latency_pressure(
    config: &Config,
    deltas: &MetricDeltas,
) -> bool {
    let threshold = ((config.auto_tuning.slo.p95_proxy_latency_ms as f64) * 1.25)
        .round()
        .max((config.auto_tuning.slo.p95_proxy_latency_ms + 50) as f64) as u64;
    deltas.segments.iter().any(|segment| {
        is_business_layer_segment(segment)
            && segment.proxied_requests_delta >= 8
            && segment.avg_proxy_latency_ms >= threshold
    })
}

pub(in crate::core::auto_tuning) fn has_critical_layered_regression(
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

pub(super) fn is_business_layer_segment(segment: &TrafficSegmentDelta) -> bool {
    matches!(segment.scope_type, "host" | "route" | "host_route")
}
