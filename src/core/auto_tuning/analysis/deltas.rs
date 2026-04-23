use crate::metrics::{MetricsSnapshot, ProxyTrafficMetricsSnapshot, ProxyTrafficSegmentSnapshot};
use std::collections::BTreeMap;

use super::super::types::*;

pub(in crate::core::auto_tuning) fn compute_deltas(
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
    let l7_cc_challenges_delta = current
        .l7_cc_challenges
        .saturating_sub(previous.l7_cc_challenges);
    let l7_cc_blocks_delta = current.l7_cc_blocks.saturating_sub(previous.l7_cc_blocks);
    let l7_cc_verified_passes_delta = current
        .l7_cc_verified_passes
        .saturating_sub(previous.l7_cc_verified_passes);
    let l7_friction_events_delta = current
        .l7_cc_challenges
        .saturating_sub(previous.l7_cc_challenges)
        .saturating_add(l7_cc_blocks_delta)
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
    let challenge_verify_rate_percent = if l7_cc_challenges_delta > 0 {
        l7_cc_verified_passes_delta as f64 * 100.0 / l7_cc_challenges_delta as f64
    } else {
        0.0
    };
    let challenge_block_rate_percent = if l7_cc_challenges_delta > 0 {
        l7_cc_blocks_delta as f64 * 100.0 / l7_cc_challenges_delta as f64
    } else {
        0.0
    };

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
        challenge_issued: l7_cc_challenges_delta,
        challenge_verified: l7_cc_verified_passes_delta,
        challenge_verify_rate_percent,
        challenge_block_rate_percent,
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

pub(in crate::core::auto_tuning) fn deltas_from_runtime(
    runtime: &AutoTuningRuntimeSnapshot,
) -> MetricDeltas {
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
        challenge_issued: runtime.last_observed_challenge_issued,
        challenge_verified: runtime.last_observed_challenge_verified,
        challenge_verify_rate_percent: runtime.last_observed_challenge_verify_rate_percent,
        challenge_block_rate_percent: runtime.last_observed_challenge_block_rate_percent,
        segments: Vec::new(),
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
