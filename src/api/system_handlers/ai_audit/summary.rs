use super::*;
use std::collections::BTreeMap;

pub(super) async fn build_ai_audit_summary(
    context: &WafContext,
    window_seconds: Option<u32>,
    sample_limit: Option<u32>,
    recent_limit: Option<u32>,
) -> ApiResult<AiAuditSummaryResponse> {
    let store = context
        .sqlite_store
        .as_deref()
        .ok_or_else(|| ApiError::conflict("SQLite store is unavailable".to_string()))?;
    let config = context.config_snapshot();
    let runtime_policy = management_runtime_policy(context);
    let now = unix_timestamp();
    let requested_window_seconds = window_seconds.unwrap_or(3600).clamp(60, 24 * 3600);
    let requested_sample_limit = sample_limit
        .unwrap_or(config.integrations.ai_audit.event_sample_limit)
        .clamp(20, 1000);
    let requested_recent_limit = recent_limit
        .unwrap_or(config.integrations.ai_audit.recent_event_limit)
        .clamp(0, 100);
    let window_seconds = scaled_limit(requested_window_seconds, runtime_policy.window_divisor, 60);
    let sample_limit = scaled_limit(requested_sample_limit, runtime_policy.sample_divisor, 20);
    let recent_limit = scaled_limit(requested_recent_limit, runtime_policy.recent_divisor, 0);
    let created_from = now.saturating_sub(window_seconds as i64);
    let mut degraded_reasons = Vec::new();
    if window_seconds != requested_window_seconds {
        degraded_reasons
            .push("management_ai_audit_window_reduced_under_runtime_pressure".to_string());
    }
    if sample_limit != requested_sample_limit {
        degraded_reasons
            .push("management_ai_audit_sample_reduced_under_runtime_pressure".to_string());
    }
    if recent_limit != requested_recent_limit {
        degraded_reasons
            .push("management_ai_audit_recent_events_reduced_under_runtime_pressure".to_string());
    }

    let result = store
        .list_security_events(&crate::storage::SecurityEventQuery {
            limit: sample_limit,
            offset: 0,
            created_from: Some(created_from),
            sort_by: crate::storage::EventSortField::CreatedAt,
            sort_direction: crate::storage::SortDirection::Desc,
            ..crate::storage::SecurityEventQuery::default()
        })
        .await
        .map_err(ApiError::internal)?;
    let storage_summary = store.metrics_summary().await.map_err(ApiError::internal)?;

    let metrics = context.metrics_snapshot().unwrap_or_default();
    let auto = context.auto_tuning_snapshot();
    let adaptive = context.adaptive_protection_snapshot();
    let recent_policy_feedback = context
        .active_ai_temp_policies()
        .into_iter()
        .take(6)
        .map(ai_audit_policy_feedback_from_entry)
        .collect::<Vec<_>>();
    let events = result
        .items
        .into_iter()
        .map(SecurityEventResponse::from)
        .collect::<Vec<_>>();
    let aggregate = summarize_audit_events(&events, recent_limit);
    let trend_windows = build_audit_trend_windows(store, now, sample_limit).await?;
    let data_quality = build_ai_audit_data_quality(
        &storage_summary,
        &aggregate,
        result.total,
        context.runtime_pressure_snapshot(),
        config.integrations.ai_audit.include_raw_event_samples,
    );
    if data_quality.analysis_confidence == "low" {
        degraded_reasons.push("management_ai_audit_low_confidence_input".to_string());
    } else if data_quality.analysis_confidence == "medium" {
        degraded_reasons.push("management_ai_audit_partially_degraded_input".to_string());
    }

    Ok(AiAuditSummaryResponse {
        generated_at: now,
        window_seconds,
        sampled_events: aggregate.sampled_events,
        total_events: result.total,
        active_rules: context.active_rule_count(),
        runtime_pressure_level: runtime_policy.pressure_level,
        degraded_reasons,
        data_quality,
        current: AiAuditCurrentStateResponse {
            adaptive_system_pressure: adaptive.system_pressure,
            adaptive_reasons: adaptive.reasons,
            l4_overload_level: metrics_l4_overload_level(&metrics),
            auto_tuning_controller_state: auto.controller_state,
            auto_tuning_last_adjust_reason: auto.last_adjust_reason,
            auto_tuning_last_adjust_diff: auto.last_adjust_diff,
            identity_pressure_percent: auto.last_observed_identity_resolution_pressure_percent,
            l7_friction_pressure_percent: auto.last_observed_l7_friction_pressure_percent,
            slow_attack_pressure_percent: auto.last_observed_slow_attack_pressure_percent,
        },
        counters: AiAuditCountersResponse {
            proxied_requests: metrics.proxied_requests,
            blocked_packets: metrics.blocked_packets,
            blocked_l4: metrics.blocked_l4,
            blocked_l7: metrics.blocked_l7,
            l7_cc_challenges: metrics.l7_cc_challenges,
            l7_cc_blocks: metrics.l7_cc_blocks,
            l7_cc_delays: metrics.l7_cc_delays,
            l7_behavior_challenges: metrics.l7_behavior_challenges,
            l7_behavior_blocks: metrics.l7_behavior_blocks,
            l7_behavior_delays: metrics.l7_behavior_delays,
            l4_bucket_budget_rejections: metrics.l4_bucket_budget_rejections,
            trusted_proxy_permit_drops: metrics.trusted_proxy_permit_drops,
            trusted_proxy_l4_degrade_actions: metrics.trusted_proxy_l4_degrade_actions,
            l4_request_budget_softened: metrics.l4_request_budget_softened,
            slow_attack_hits: metrics.slow_attack_idle_timeouts
                + metrics.slow_attack_header_timeouts
                + metrics.slow_attack_body_timeouts
                + metrics.slow_attack_tls_handshake_hits
                + metrics.slow_attack_blocks,
            average_proxy_latency_micros: metrics.average_proxy_latency_micros,
        },
        action_breakdown: top_count_items(aggregate.action_breakdown, 8),
        provider_breakdown: top_count_items(aggregate.provider_breakdown, 6),
        identity_states: top_count_items(aggregate.identity_states, 8),
        primary_signals: top_count_items(aggregate.primary_signals, 8),
        labels: top_count_items(aggregate.labels, 12),
        top_source_ips: top_count_items(aggregate.top_source_ips, 8),
        top_routes: top_count_items(aggregate.top_routes, 8),
        top_hosts: top_count_items(aggregate.top_hosts, 8),
        safeline_correlation: AiAuditSafeLineCorrelationResponse {
            safeline_events: aggregate.safeline_events,
            rust_events: aggregate.rust_events,
            rust_persistence_percent: rust_persistence_percent(
                aggregate.safeline_events,
                aggregate.rust_events,
            ),
            safeline_top_hosts: top_count_items(aggregate.safeline_hosts.clone(), 6),
            rust_top_hosts: top_count_items(aggregate.rust_hosts.clone(), 6),
            overlap_hosts: overlap_count_items(&aggregate.safeline_hosts, &aggregate.rust_hosts, 6),
            overlap_routes: overlap_count_items(
                &aggregate.safeline_routes,
                &aggregate.rust_routes,
                6,
            ),
            overlap_source_ips: overlap_count_items(
                &aggregate.safeline_source_ips,
                &aggregate.rust_source_ips,
                6,
            ),
            persistent_overlap_hosts: persistent_overlap_items(
                &aggregate.safeline_hosts,
                &aggregate.rust_hosts,
                6,
            ),
            persistent_overlap_routes: persistent_overlap_items(
                &aggregate.safeline_routes,
                &aggregate.rust_routes,
                6,
            ),
            persistent_overlap_source_ips: persistent_overlap_items(
                &aggregate.safeline_source_ips,
                &aggregate.rust_source_ips,
                6,
            ),
        },
        trend_windows,
        recent_policy_feedback,
        recent_events: aggregate.recent_events,
    })
}

pub(crate) async fn build_ai_audit_summary_for_context(
    context: &WafContext,
    window_seconds: Option<u32>,
    sample_limit: Option<u32>,
    recent_limit: Option<u32>,
) -> anyhow::Result<AiAuditSummaryResponse> {
    build_ai_audit_summary(context, window_seconds, sample_limit, recent_limit)
        .await
        .map_err(|err| anyhow::anyhow!("build ai audit summary failed: {:?}", err))
}

#[derive(Debug, Default)]
struct AuditEventAggregate {
    sampled_events: u32,
    recent_events: Vec<AiAuditEventSampleResponse>,
    action_breakdown: BTreeMap<String, u64>,
    provider_breakdown: BTreeMap<String, u64>,
    identity_states: BTreeMap<String, u64>,
    primary_signals: BTreeMap<String, u64>,
    labels: BTreeMap<String, u64>,
    top_source_ips: BTreeMap<String, u64>,
    top_routes: BTreeMap<String, u64>,
    top_hosts: BTreeMap<String, u64>,
    safeline_hosts: BTreeMap<String, u64>,
    rust_hosts: BTreeMap<String, u64>,
    safeline_routes: BTreeMap<String, u64>,
    rust_routes: BTreeMap<String, u64>,
    safeline_source_ips: BTreeMap<String, u64>,
    rust_source_ips: BTreeMap<String, u64>,
    safeline_events: u64,
    rust_events: u64,
    blocked_events: u64,
    challenged_events: u64,
    delayed_events: u64,
}

fn summarize_audit_events(
    events: &[SecurityEventResponse],
    recent_limit: u32,
) -> AuditEventAggregate {
    let mut aggregate = AuditEventAggregate {
        sampled_events: events.len() as u32,
        ..AuditEventAggregate::default()
    };

    for event in events {
        let is_safeline = event.provider.as_deref() == Some("safeline");
        let event_sample = event.clone();
        if aggregate.recent_events.len() < recent_limit as usize {
            aggregate
                .recent_events
                .push(AiAuditEventSampleResponse::from(event_sample));
        }
        increment_map(&mut aggregate.action_breakdown, &event.action);
        increment_map(
            &mut aggregate.provider_breakdown,
            event.provider.as_deref().unwrap_or("local"),
        );
        increment_map(&mut aggregate.top_source_ips, &event.source_ip);
        match event.action.as_str() {
            "block" | "respond" => aggregate.blocked_events += 1,
            "challenge" => aggregate.challenged_events += 1,
            "delay" => aggregate.delayed_events += 1,
            _ => {}
        }
        if is_safeline {
            aggregate.safeline_events += 1;
            increment_map(&mut aggregate.safeline_source_ips, &event.source_ip);
        } else {
            aggregate.rust_events += 1;
            increment_map(&mut aggregate.rust_source_ips, &event.source_ip);
        }
        if let Some(uri) = event.uri.as_deref() {
            increment_map(&mut aggregate.top_routes, uri);
            if is_safeline {
                increment_map(&mut aggregate.safeline_routes, uri);
            } else {
                increment_map(&mut aggregate.rust_routes, uri);
            }
        }
        if let Some(host) = ai_audit_event_host(event) {
            increment_map(&mut aggregate.top_hosts, &host);
            if is_safeline {
                increment_map(&mut aggregate.safeline_hosts, &host);
            } else {
                increment_map(&mut aggregate.rust_hosts, &host);
            }
        }
        if let Some(summary) = event.decision_summary.as_ref() {
            if let Some(identity_state) = summary.identity_state.as_deref() {
                increment_map(&mut aggregate.identity_states, identity_state);
            }
            increment_map(&mut aggregate.primary_signals, &summary.primary_signal);
            for label in &summary.labels {
                increment_map(&mut aggregate.labels, label);
            }
        }
    }

    aggregate
}

async fn build_audit_trend_windows(
    store: &crate::storage::SqliteStore,
    now: i64,
    sample_limit: u32,
) -> ApiResult<Vec<AiAuditTrendWindowResponse>> {
    let windows = [
        ("last_5m", 5 * 60u32),
        ("last_15m", 15 * 60u32),
        ("last_60m", 60 * 60u32),
    ];
    let mut items = Vec::with_capacity(windows.len());

    for (label, seconds) in windows {
        let result = store
            .list_security_events(&crate::storage::SecurityEventQuery {
                limit: sample_limit.min(120),
                offset: 0,
                created_from: Some(now.saturating_sub(seconds as i64)),
                sort_by: crate::storage::EventSortField::CreatedAt,
                sort_direction: crate::storage::SortDirection::Desc,
                ..crate::storage::SecurityEventQuery::default()
            })
            .await
            .map_err(ApiError::internal)?;
        let events = result
            .items
            .into_iter()
            .map(SecurityEventResponse::from)
            .collect::<Vec<_>>();
        let aggregate = summarize_audit_events(&events, 0);
        items.push(AiAuditTrendWindowResponse {
            label: label.to_string(),
            window_seconds: seconds,
            total_events: result.total,
            sampled_events: aggregate.sampled_events,
            blocked_events: aggregate.blocked_events,
            challenged_events: aggregate.challenged_events,
            delayed_events: aggregate.delayed_events,
            action_breakdown: top_count_items(aggregate.action_breakdown, 6),
            top_source_ips: top_count_items(aggregate.top_source_ips, 5),
            top_routes: top_count_items(aggregate.top_routes, 5),
            top_hosts: top_count_items(aggregate.top_hosts, 5),
        });
    }

    Ok(items)
}

fn build_ai_audit_data_quality(
    storage_summary: &crate::storage::StorageMetricsSummary,
    aggregate: &AuditEventAggregate,
    total_events: u64,
    runtime_pressure: crate::core::RuntimePressureSnapshot,
    raw_samples_included: bool,
) -> AiAuditDataQualityResponse {
    let sqlite_queue_usage_percent = if storage_summary.queue_capacity == 0 {
        0.0
    } else {
        ((storage_summary.queue_depth as f64 / storage_summary.queue_capacity as f64) * 100.0)
            .clamp(0.0, 100.0)
    };
    let sample_coverage_ratio = if total_events == 0 {
        1.0
    } else {
        let sampled = aggregate.sampled_events as f64;
        let total = total_events as f64;
        (sampled / total).clamp(0.0, 1.0)
    };
    let persisted_plus_dropped =
        storage_summary.security_events + storage_summary.dropped_security_events;
    let persistence_coverage_ratio = if persisted_plus_dropped == 0 {
        1.0
    } else {
        (storage_summary.security_events as f64 / persisted_plus_dropped as f64).clamp(0.0, 1.0)
    };
    let detail_slimming_active =
        runtime_pressure.trim_event_persistence || sqlite_queue_usage_percent >= 75.0;
    let analysis_confidence = if storage_summary.dropped_security_events > 0
        || runtime_pressure.level == "attack"
        || persistence_coverage_ratio < 0.95
    {
        "low"
    } else if detail_slimming_active || runtime_pressure.level == "high" {
        "medium"
    } else {
        "high"
    };

    AiAuditDataQualityResponse {
        persisted_security_events: storage_summary.security_events,
        dropped_security_events: storage_summary.dropped_security_events,
        sqlite_queue_depth: storage_summary.queue_depth,
        sqlite_queue_capacity: storage_summary.queue_capacity,
        sqlite_queue_usage_percent,
        detail_slimming_active,
        sample_coverage_ratio,
        persistence_coverage_ratio,
        raw_samples_included,
        recent_events_count: aggregate.recent_events.len() as u32,
        analysis_confidence: analysis_confidence.to_string(),
    }
}

fn increment_map(map: &mut BTreeMap<String, u64>, key: &str) {
    *map.entry(key.to_string()).or_insert(0) += 1;
}

fn overlap_count_items(
    left: &BTreeMap<String, u64>,
    right: &BTreeMap<String, u64>,
    limit: usize,
) -> Vec<AiAuditCountItem> {
    let mut items = left
        .iter()
        .filter_map(|(key, left_count)| {
            let right_count = right.get(key)?;
            Some(AiAuditCountItem {
                key: key.clone(),
                count: (*left_count).min(*right_count),
            })
        })
        .collect::<Vec<_>>();
    items.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.key.cmp(&b.key)));
    items.truncate(limit);
    items
}

fn persistent_overlap_items(
    safeline: &BTreeMap<String, u64>,
    rust: &BTreeMap<String, u64>,
    limit: usize,
) -> Vec<AiAuditCountItem> {
    let mut items = safeline
        .iter()
        .filter_map(|(key, safeline_count)| {
            let rust_count = rust.get(key)?;
            if *rust_count > *safeline_count {
                Some(AiAuditCountItem {
                    key: key.clone(),
                    count: rust_count.saturating_sub(*safeline_count),
                })
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    items.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.key.cmp(&b.key)));
    items.truncate(limit);
    items
}

fn rust_persistence_percent(safeline_events: u64, rust_events: u64) -> f64 {
    if safeline_events == 0 {
        return if rust_events > 0 { 100.0 } else { 0.0 };
    }
    ((rust_events as f64 / safeline_events as f64) * 100.0).clamp(0.0, 999.0)
}

fn ai_audit_event_host(event: &SecurityEventResponse) -> Option<String> {
    event.provider_site_domain.clone().or_else(|| {
        event
            .details_json
            .as_deref()
            .and_then(|raw| serde_json::from_str::<serde_json::Value>(raw).ok())
            .as_ref()
            .and_then(|details| {
                details
                    .get("l7_cc")
                    .and_then(|value| value.get("host"))
                    .and_then(|value| value.as_str())
                    .map(ToOwned::to_owned)
                    .or_else(|| {
                        details
                            .get("client_identity")
                            .and_then(|value| value.get("headers"))
                            .and_then(|value| value.as_array())
                            .and_then(|headers| {
                                headers.iter().find_map(|entry| {
                                    let pair = entry.as_array()?;
                                    let key = pair.first()?.as_str()?.trim();
                                    let value = pair.get(1)?.as_str()?.trim();
                                    (key.eq_ignore_ascii_case("host") && !value.is_empty())
                                        .then(|| value.to_string())
                                })
                            })
                    })
            })
    })
}

fn top_count_items(map: BTreeMap<String, u64>, limit: usize) -> Vec<AiAuditCountItem> {
    let mut items = map
        .into_iter()
        .map(|(key, count)| AiAuditCountItem { key, count })
        .collect::<Vec<_>>();
    items.sort_by(|left, right| right.count.cmp(&left.count).then(left.key.cmp(&right.key)));
    items.truncate(limit);
    items
}

fn metrics_l4_overload_level(metrics: &crate::metrics::MetricsSnapshot) -> String {
    if metrics.trusted_proxy_l4_degrade_actions > 0
        || metrics.l4_bucket_budget_rejections > 0
        || metrics.l4_request_budget_softened > 0
    {
        "high".to_string()
    } else {
        "normal".to_string()
    }
}
