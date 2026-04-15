use super::*;
use std::collections::BTreeMap;

#[derive(Debug, Clone)]
struct ManagementRuntimePolicy {
    pressure_level: String,
    window_divisor: u32,
    sample_divisor: u32,
    recent_divisor: u32,
    force_local_rules: bool,
}

fn management_runtime_policy(context: &WafContext) -> ManagementRuntimePolicy {
    let pressure = context.runtime_pressure_snapshot();
    match pressure.level {
        "attack" => ManagementRuntimePolicy {
            pressure_level: pressure.level.to_string(),
            window_divisor: 4,
            sample_divisor: 4,
            recent_divisor: 4,
            force_local_rules: true,
        },
        "high" => ManagementRuntimePolicy {
            pressure_level: pressure.level.to_string(),
            window_divisor: 2,
            sample_divisor: 2,
            recent_divisor: 2,
            force_local_rules: false,
        },
        _ => ManagementRuntimePolicy {
            pressure_level: pressure.level.to_string(),
            window_divisor: 1,
            sample_divisor: 1,
            recent_divisor: 1,
            force_local_rules: false,
        },
    }
}

fn scaled_limit(value: u32, divisor: u32, min: u32) -> u32 {
    if divisor <= 1 {
        value.max(min)
    } else {
        value.saturating_div(divisor).max(min)
    }
}

fn management_degraded_reason(enabled: bool, reason: &str) -> Vec<String> {
    enabled.then(|| reason.to_string()).into_iter().collect()
}

pub(super) async fn health_handler(State(state): State<ApiState>) -> Json<HealthResponse> {
    let upstream = state.context.upstream_health_snapshot();
    Json(HealthResponse {
        status: if upstream.healthy {
            "healthy".to_string()
        } else {
            "degraded".to_string()
        },
        version: env!("CARGO_PKG_VERSION").to_string(),
        upstream_healthy: upstream.healthy,
        upstream_last_check_at: upstream.last_check_at,
        upstream_last_error: upstream.last_error,
    })
}

pub(super) async fn metrics_handler(State(state): State<ApiState>) -> Json<MetricsResponse> {
    let metrics = state.context.metrics_snapshot();
    let storage_summary = if let Some(store) = state.context.sqlite_store.as_ref() {
        match store.metrics_summary().await {
            Ok(summary) => Some(summary),
            Err(err) => {
                log::warn!("Failed to query SQLite metrics summary: {}", err);
                None
            }
        }
    } else {
        None
    };

    Json(build_metrics_response(
        metrics,
        state.context.active_rule_count(),
        storage_summary,
        state
            .context
            .l4_inspector()
            .map(|inspector| inspector.get_statistics().behavior.overview),
        state.context.runtime_pressure_snapshot(),
    ))
}

pub(super) async fn traffic_map_handler(
    State(state): State<ApiState>,
    Query(params): Query<TrafficMapQueryParams>,
) -> Json<TrafficMapResponse> {
    let policy = management_runtime_policy(state.context.as_ref());
    let requested_window = params.window_seconds.unwrap_or(60);
    let effective_window = scaled_limit(requested_window, policy.window_divisor, 10);
    let snapshot = state.context.traffic_map_snapshot(effective_window).await;

    Json(TrafficMapResponse {
        scope: snapshot.scope,
        window_seconds: snapshot.window_seconds,
        generated_at: snapshot.generated_at,
        runtime_pressure_level: policy.pressure_level,
        degraded_reasons: management_degraded_reason(
            effective_window != requested_window,
            "management_traffic_map_window_reduced_under_runtime_pressure",
        ),
        origin_node: TrafficMapNodeResponse {
            id: snapshot.origin_node.id,
            name: snapshot.origin_node.name,
            region: snapshot.origin_node.region,
            role: snapshot.origin_node.role,
            lat: snapshot.origin_node.lat,
            lng: snapshot.origin_node.lng,
            traffic_weight: snapshot.origin_node.traffic_weight,
            request_count: snapshot.origin_node.request_count,
            blocked_count: snapshot.origin_node.blocked_count,
            bandwidth_mbps: snapshot.origin_node.bandwidth_mbps,
            last_seen_at: snapshot.origin_node.last_seen_at,
        },
        nodes: snapshot
            .nodes
            .into_iter()
            .map(|item| TrafficMapNodeResponse {
                id: item.id,
                name: item.name,
                region: item.region,
                role: item.role,
                lat: item.lat,
                lng: item.lng,
                traffic_weight: item.traffic_weight,
                request_count: item.request_count,
                blocked_count: item.blocked_count,
                bandwidth_mbps: item.bandwidth_mbps,
                last_seen_at: item.last_seen_at,
            })
            .collect(),
        flows: snapshot
            .flows
            .into_iter()
            .map(|item| TrafficMapFlowResponse {
                id: item.id,
                node_id: item.node_id,
                direction: item.direction,
                decision: item.decision,
                request_count: item.request_count,
                bytes: item.bytes,
                bandwidth_mbps: item.bandwidth_mbps,
                average_latency_ms: item.average_latency_ms,
                last_seen_at: item.last_seen_at,
            })
            .collect(),
        active_node_count: snapshot.active_node_count,
        peak_bandwidth_mbps: snapshot.peak_bandwidth_mbps,
        allowed_flow_count: snapshot.allowed_flow_count,
        blocked_flow_count: snapshot.blocked_flow_count,
        live_traffic_score: snapshot.live_traffic_score,
    })
}

pub(super) async fn ai_audit_summary_handler(
    State(state): State<ApiState>,
    Query(params): Query<AiAuditSummaryQueryParams>,
) -> ApiResult<Json<AiAuditSummaryResponse>> {
    Ok(Json(
        build_ai_audit_summary(
            &state,
            params.window_seconds,
            params.sample_limit,
            params.recent_limit,
        )
        .await?,
    ))
}

pub(super) async fn ai_audit_report_handler(
    State(state): State<ApiState>,
) -> ApiResult<Json<AiAuditReportResponse>> {
    let store = sqlite_store(&state)?;
    let result = store
        .list_ai_audit_reports(&crate::storage::AiAuditReportQuery {
            limit: 1,
            offset: 0,
            feedback_status: None,
        })
        .await
        .map_err(ApiError::internal)?;
    let Some(entry) = result.items.into_iter().next() else {
        return Err(ApiError::not_found(
            "暂无 AI 审计历史，请先执行一次 AI 审计",
        ));
    };
    let report = crate::api::ai_audit::history_item_from_entry(entry)
        .map_err(ApiError::internal)?
        .report;
    Ok(Json(report))
}

pub(super) async fn run_ai_audit_report_handler(
    State(state): State<ApiState>,
    ExtractJson(payload): ExtractJson<AiAuditRunRequest>,
) -> ApiResult<Json<AiAuditReportResponse>> {
    let runtime_policy = management_runtime_policy(state.context.as_ref());
    let params = AiAuditReportQueryParams {
        window_seconds: payload.window_seconds,
        sample_limit: payload.sample_limit,
        recent_limit: payload.recent_limit,
        provider: payload.provider,
        fallback_to_rules: payload.fallback_to_rules,
    };
    let config = state.context.config_snapshot();
    let mut execution = crate::api::ai_audit::resolve_report_execution(&config, &params);
    if runtime_policy.force_local_rules
        && execution.provider != crate::api::ai_audit::AiAuditProvider::LocalRules
    {
        execution.provider = crate::api::ai_audit::AiAuditProvider::LocalRules;
        execution
            .execution_notes
            .push("runtime pressure forced ai audit into local_rules mode".to_string());
    }
    let summary_query = crate::api::ai_audit::summary_query_from_report(&params);
    let summary = build_ai_audit_summary(
        &state,
        summary_query.window_seconds,
        summary_query.sample_limit,
        summary_query.recent_limit,
    )
    .await?;
    let mut report =
        crate::api::ai_audit::execute_report(execution, summary, build_ai_audit_report).await?;
    if runtime_policy.force_local_rules {
        report
            .degraded_reasons
            .push("management_ai_audit_forced_local_rules_under_runtime_pressure".to_string());
    }
    if let Some(store) = state.context.sqlite_store.as_ref() {
        let persist_result = match serde_json::to_string(&report) {
            Ok(report_json) => store
                .create_ai_audit_report(
                    report.generated_at,
                    &report.provider_used,
                    report.fallback_used,
                    &report.risk_level,
                    &report.headline,
                    &report_json,
                )
                .await
                .map_err(ApiError::internal),
            Err(err) => Err(ApiError::internal(err)),
        };
        match persist_result {
            Ok(id) => report.report_id = Some(id),
            Err(err) => {
                log::warn!("Failed to persist AI audit report: {:?}", err);
                report
                    .execution_notes
                    .push("failed to persist ai audit report snapshot".to_string());
            }
        }
        if config.integrations.ai_audit.auto_apply_temp_policies {
            match apply_ai_temp_policies_from_report(
                store,
                report.report_id,
                &report,
                &config.integrations.ai_audit,
            )
            .await
            {
                Ok(applied) => {
                    if applied > 0 {
                        report.execution_notes.push(format!(
                            "auto applied {} temporary cc/behavior policies",
                            applied
                        ));
                    }
                }
                Err(err) => {
                    log::warn!("Failed to auto-apply AI temp policies: {:?}", err);
                    report
                        .execution_notes
                        .push("failed to auto apply ai temporary policies".to_string());
                }
            }
            let _ = state.context.refresh_ai_temp_policies().await;
        }
    }
    Ok(Json(report))
}

pub(super) async fn list_ai_audit_reports_handler(
    State(state): State<ApiState>,
    Query(params): Query<AiAuditReportsQueryParams>,
) -> ApiResult<Json<AiAuditReportsResponse>> {
    let store = sqlite_store(&state)?;
    let result = store
        .list_ai_audit_reports(&crate::storage::AiAuditReportQuery {
            limit: params.limit.unwrap_or(20),
            offset: params.offset.unwrap_or(0),
            feedback_status: params.feedback_status,
        })
        .await
        .map_err(ApiError::internal)?;

    let reports = result
        .items
        .into_iter()
        .map(crate::api::ai_audit::history_item_from_entry)
        .collect::<Result<Vec<_>, _>>()
        .map_err(ApiError::internal)?;

    Ok(Json(AiAuditReportsResponse {
        total: result.total,
        limit: result.limit,
        offset: result.offset,
        reports,
    }))
}

pub(super) async fn list_ai_temp_policies_handler(
    State(state): State<ApiState>,
) -> ApiResult<Json<AiTempPoliciesResponse>> {
    let items = state.context.active_ai_temp_policies();
    let summary = build_ai_audit_summary(&state, Some(900), Some(120), Some(0)).await?;
    Ok(Json(AiTempPoliciesResponse {
        total: items.len() as u32,
        policies: items
            .into_iter()
            .map(|item| ai_temp_policy_response_from_entry(item, &summary))
            .collect(),
    }))
}

pub(super) async fn delete_ai_temp_policy_handler(
    State(state): State<ApiState>,
    Path(id): Path<i64>,
) -> ApiResult<Json<WriteStatusResponse>> {
    let store = sqlite_store(&state)?;
    let deleted = store
        .delete_ai_temp_policy(id)
        .await
        .map_err(ApiError::internal)?;
    if !deleted {
        return Err(ApiError::not_found("未找到对应的 AI 临时策略"));
    }
    state
        .context
        .refresh_ai_temp_policies()
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(WriteStatusResponse {
        success: true,
        message: "AI 临时策略已撤销".to_string(),
    }))
}

pub(super) async fn update_ai_audit_report_feedback_handler(
    State(state): State<ApiState>,
    Path(id): Path<i64>,
    ExtractJson(payload): ExtractJson<AiAuditFeedbackUpdateRequest>,
) -> ApiResult<Json<WriteStatusResponse>> {
    let store = sqlite_store(&state)?;
    let feedback_status = payload
        .feedback_status
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if let Some(status) = feedback_status {
        let normalized = status.to_ascii_lowercase();
        if !matches!(
            normalized.as_str(),
            "confirmed" | "false_positive" | "follow_up"
        ) {
            return Err(ApiError::bad_request(
                "feedback_status 仅支持 confirmed / false_positive / follow_up",
            ));
        }
    }
    let updated = store
        .update_ai_audit_report_feedback(
            id,
            feedback_status,
            payload
                .feedback_notes
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty()),
        )
        .await
        .map_err(ApiError::internal)?;
    if !updated {
        return Err(ApiError::not_found("未找到对应的 AI 审计报告"));
    }

    Ok(Json(WriteStatusResponse {
        success: true,
        message: "AI 审计反馈已更新".to_string(),
    }))
}

async fn build_ai_audit_summary(
    state: &ApiState,
    window_seconds: Option<u32>,
    sample_limit: Option<u32>,
    recent_limit: Option<u32>,
) -> ApiResult<AiAuditSummaryResponse> {
    let store = sqlite_store(&state)?;
    let config = state.context.config_snapshot();
    let runtime_policy = management_runtime_policy(state.context.as_ref());
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

    let metrics = state.context.metrics_snapshot().unwrap_or_default();
    let auto = state.context.auto_tuning_snapshot();
    let adaptive = state.context.adaptive_protection_snapshot();
    let recent_policy_feedback = state
        .context
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
        state.context.runtime_pressure_snapshot(),
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
        active_rules: state.context.active_rule_count(),
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

fn build_ai_audit_report(summary: AiAuditSummaryResponse) -> AiAuditReportResponse {
    let mut findings = Vec::new();
    let mut recommendations = Vec::new();
    let mut executive_summary = Vec::new();
    let mut suggested_local_rules = Vec::new();
    let low_confidence_input = summary.data_quality.analysis_confidence == "low";
    let medium_confidence_input = summary.data_quality.analysis_confidence == "medium";

    if low_confidence_input {
        executive_summary.push(format!(
            "当前审计输入可信度偏低，事件持久化覆盖率约 {:.1}%，已丢弃 {} 条安全事件。",
            summary.data_quality.persistence_coverage_ratio * 100.0,
            summary.data_quality.dropped_security_events
        ));
        recommendations.push(AiAuditReportRecommendation {
            key: "manual_review_due_to_degraded_input".to_string(),
            priority: "high".to_string(),
            title: "优先人工复核本次审计输入".to_string(),
            action: "当前高压或写入降级已影响审计样本完整性，建议先复核 SQLite 队列压力、事件丢弃和热点对象，再决定是否临时加压。".to_string(),
            rationale: "输入失真时继续自动收紧，容易把系统压力误判成攻击结论。".to_string(),
            action_type: "investigate".to_string(),
            rule_suggestion_key: None,
        });
    } else if medium_confidence_input {
        executive_summary.push(format!(
            "当前审计输入存在一定降级，事件详情可能已瘦身，建议对强结论保持谨慎。"
        ));
    }

    if !summary.safeline_correlation.overlap_hosts.is_empty()
        || !summary.safeline_correlation.overlap_routes.is_empty()
    {
        let top_host = summary
            .safeline_correlation
            .overlap_hosts
            .first()
            .map(|item| item.key.clone());
        let top_route = summary
            .safeline_correlation
            .overlap_routes
            .first()
            .map(|item| item.key.clone());
        findings.push(AiAuditReportFinding {
            key: "safeline_rust_overlap_detected".to_string(),
            severity: "high".to_string(),
            title: "雷池与 Rust 观察到同一批热点对象".to_string(),
            detail: format!(
                "最近窗口里雷池事件 {} 条，Rust 本地事件 {} 条，并且存在共同热点 host/route，说明前置拦截后仍有持续压力回流。",
                summary.safeline_correlation.safeline_events,
                summary.safeline_correlation.rust_events
            ),
            evidence: vec![
                format!(
                    "overlap_hosts={}",
                    summary.safeline_correlation.overlap_hosts.len()
                ),
                format!(
                    "overlap_routes={}",
                    summary.safeline_correlation.overlap_routes.len()
                ),
                format!(
                    "overlap_source_ips={}",
                    summary.safeline_correlation.overlap_source_ips.len()
                ),
            ],
        });
        recommendations.push(AiAuditReportRecommendation {
            key: "tighten_safeline_overlap_objects".to_string(),
            priority: "high".to_string(),
            title: "优先收紧雷池与 Rust 共同热点".to_string(),
            action: format!(
                "围绕共同热点{}{}提高 challenge / delay / temp block 强度，重点观察雷池已拦截但仍持续回流的对象。",
                top_host
                    .as_deref()
                    .map(|value| format!(" host {value}"))
                    .unwrap_or_default(),
                top_route
                    .as_deref()
                    .map(|value| format!(" route {value}"))
                    .unwrap_or_default()
            ),
            rationale: "共同热点比单边热点更能说明攻击还没有被完全吸收，适合作为专项护盾的优先收紧对象。".to_string(),
            action_type: "add_rule".to_string(),
            rule_suggestion_key: Some("tighten_safeline_overlap_route".to_string()),
        });
        if let Some(route) = top_route {
            suggested_local_rules.push(AiAuditSuggestedRuleResponse {
                key: "tighten_safeline_overlap_route".to_string(),
                title: "收紧雷池重叠热点路径".to_string(),
                policy_type: "tighten_route_cc".to_string(),
                layer: "l7".to_string(),
                scope_type: "route".to_string(),
                scope_value: route,
                target: "safeline_overlap_route".to_string(),
                action: "tighten_route_cc".to_string(),
                operator: "prefix".to_string(),
                suggested_value: "75".to_string(),
                ttl_secs: 1200,
                auto_apply: true,
                rationale:
                    "雷池与 Rust 同时观察到的热点路径更适合短期提高摩擦，压缩持续型 CC 的回流空间。"
                        .to_string(),
            });
        }
    }

    if !summary
        .safeline_correlation
        .persistent_overlap_hosts
        .is_empty()
        || !summary
            .safeline_correlation
            .persistent_overlap_routes
            .is_empty()
    {
        let persistent_route = summary
            .safeline_correlation
            .persistent_overlap_routes
            .first()
            .map(|item| item.key.clone());
        findings.push(AiAuditReportFinding {
            key: "safeline_relief_incomplete".to_string(),
            severity: "high".to_string(),
            title: "雷池拦截后仍有未回落的持续热点".to_string(),
            detail: format!(
                "Rust 持续压力约为雷池事件量的 {:.1}%，并且存在在雷池之后依旧扩大的热点对象，说明前置拦截尚未完全压住回流。",
                summary.safeline_correlation.rust_persistence_percent
            ),
            evidence: vec![
                format!(
                    "persistent_overlap_hosts={}",
                    summary.safeline_correlation.persistent_overlap_hosts.len()
                ),
                format!(
                    "persistent_overlap_routes={}",
                    summary.safeline_correlation.persistent_overlap_routes.len()
                ),
                format!(
                    "persistent_overlap_source_ips={}",
                    summary.safeline_correlation.persistent_overlap_source_ips.len()
                ),
            ],
        });
        recommendations.push(AiAuditReportRecommendation {
            key: "raise_post_safeline_friction".to_string(),
            priority: "high".to_string(),
            title: "对雷池后持续热点加一层摩擦".to_string(),
            action: format!(
                "优先对雷池后仍未回落的对象{}追加 delay / challenge / temp block，避免同类流量在 Rust 层继续消耗连接和行为状态。",
                persistent_route
                    .as_deref()
                    .map(|value| format!("，重点观察 route {value}"))
                    .unwrap_or_default()
            ),
            rationale: "只有看到雷池后仍持续扩大的对象，AI 才能更准确地做最后一道补刀，而不是对已经被吸收的热点重复加压。".to_string(),
            action_type: "add_rule".to_string(),
            rule_suggestion_key: Some("raise_post_safeline_friction".to_string()),
        });
        if let Some(route) = persistent_route {
            suggested_local_rules.push(AiAuditSuggestedRuleResponse {
                key: "raise_post_safeline_friction".to_string(),
                title: "提高雷池后持续热点路径摩擦".to_string(),
                policy_type: "increase_delay".to_string(),
                layer: "l7".to_string(),
                scope_type: "route".to_string(),
                scope_value: route,
                target: "post_safeline_persistent_route".to_string(),
                action: "increase_delay".to_string(),
                operator: "prefix".to_string(),
                suggested_value: "350".to_string(),
                ttl_secs: 900,
                auto_apply: true,
                rationale: "对雷池之后仍持续扩大的热点路径增加延迟，可以优先压降连接和请求节奏，再观察是否需要升级到更强动作。".to_string(),
            });
        }
    }

    if summary.current.identity_pressure_percent >= 5.0 {
        findings.push(AiAuditReportFinding {
            key: "identity_pressure_high".to_string(),
            severity: "high".to_string(),
            title: "CDN 身份解析压力偏高".to_string(),
            detail: format!(
                "identity pressure 为 {:.2}%，说明可信代理流量里仍有较多未解析或受限处理请求。",
                summary.current.identity_pressure_percent
            ),
            evidence: vec![
                format!(
                    "trusted_proxy_permit_drops={}",
                    summary.counters.trusted_proxy_permit_drops
                ),
                format!(
                    "trusted_proxy_l4_degrade_actions={}",
                    summary.counters.trusted_proxy_l4_degrade_actions
                ),
                format!(
                    "l4_request_budget_softened={}",
                    summary.counters.l4_request_budget_softened
                ),
            ],
        });
        recommendations.push(AiAuditReportRecommendation {
            key: "review_real_ip_chain".to_string(),
            priority: "high".to_string(),
            title: "复核 CDN 回源真实 IP 链路".to_string(),
            action: "检查自定义真实 IP 头是否稳定透传，并核对可信 CDN CIDR 列表是否完整。"
                .to_string(),
            rationale: "身份解析不稳会让 L4/L7 自动化长期处在收紧模式，影响可用性和判定精度。"
                .to_string(),
            action_type: "investigate".to_string(),
            rule_suggestion_key: Some("tighten_forward_identity_checks".to_string()),
        });
        suggested_local_rules.push(AiAuditSuggestedRuleResponse {
            key: "tighten_forward_identity_checks".to_string(),
            title: "收紧转发身份链路校验".to_string(),
            policy_type: "raise_identity_risk".to_string(),
            layer: "l7".to_string(),
            scope_type: "host".to_string(),
            scope_value: summary
                .top_hosts
                .first()
                .map(|item| item.key.clone())
                .unwrap_or_else(|| "*".to_string()),
            target: "trusted_proxy_identity".to_string(),
            action: "raise_identity_risk".to_string(),
            operator: "tighten".to_string(),
            suggested_value: "prefer_verified_forward_chain".to_string(),
            ttl_secs: 1800,
            auto_apply: true,
            rationale: "当身份压力持续升高时，应优先减少未解析转发流量进入宽松路径。".to_string(),
        });
    }

    if summary.current.l7_friction_pressure_percent >= 20.0 {
        findings.push(AiAuditReportFinding {
            key: "l7_friction_high".to_string(),
            severity: "high".to_string(),
            title: "L7 摩擦信号明显升高".to_string(),
            detail: format!(
                "l7 friction 为 {:.2}%，说明 challenge / block / delay 明显增多。",
                summary.current.l7_friction_pressure_percent
            ),
            evidence: vec![
                format!("l7_cc_challenges={}", summary.counters.l7_cc_challenges),
                format!("l7_cc_blocks={}", summary.counters.l7_cc_blocks),
                format!("l7_behavior_blocks={}", summary.counters.l7_behavior_blocks),
            ],
        });
        recommendations.push(AiAuditReportRecommendation {
            key: "review_hot_signals".to_string(),
            priority: "high".to_string(),
            title: "排查热点主信号和标签".to_string(),
            action: "优先查看 primary_signals、labels、top_routes，确认是否存在单一路径或单类标签持续主导。".to_string(),
            rationale: "L7 摩擦升高通常意味着某类攻击或误伤模式已经形成稳定热点。".to_string(),
            action_type: "investigate".to_string(),
            rule_suggestion_key: Some("raise_hot_route_friction".to_string()),
        });
        suggested_local_rules.push(AiAuditSuggestedRuleResponse {
            key: "raise_hot_route_friction".to_string(),
            title: "提高热点路径摩擦".to_string(),
            policy_type: "tighten_route_cc".to_string(),
            layer: "l7".to_string(),
            scope_type: "route".to_string(),
            scope_value: summary
                .top_routes
                .first()
                .map(|item| item.key.clone())
                .unwrap_or_else(|| "/".to_string()),
            target: "hot_route_threshold".to_string(),
            action: "tighten_route_cc".to_string(),
            operator: "decrease_threshold".to_string(),
            suggested_value: "80".to_string(),
            ttl_secs: 900,
            auto_apply: true,
            rationale: "当热点信号稳定占优时，应优先收紧热点路径的 challenge 和 block 阈值。"
                .to_string(),
        });
        if let Some(top_source) = summary.top_source_ips.first() {
            suggested_local_rules.push(AiAuditSuggestedRuleResponse {
                key: "auto_temp_block_top_source".to_string(),
                title: "临时阻断热点来源".to_string(),
                policy_type: "add_temp_block".to_string(),
                layer: "l7".to_string(),
                scope_type: "source_ip".to_string(),
                scope_value: top_source.key.clone(),
                target: "source_ip".to_string(),
                action: "add_temp_block".to_string(),
                operator: "equals".to_string(),
                suggested_value: top_source.count.to_string(),
                ttl_secs: 1800,
                auto_apply: true,
                rationale: "当单一来源持续主导高摩擦流量时，可先施加短时阻断压降。".to_string(),
            });
            recommendations.push(AiAuditReportRecommendation {
                key: "auto_temp_block_top_source".to_string(),
                priority: "high".to_string(),
                title: "对热点来源启用临时阻断".to_string(),
                action: format!(
                    "对来源 {} 启用短时 temp block，并观察摩擦压力是否回落。",
                    top_source.key
                ),
                rationale: "适用于已被多类信号重复指向且持续制造压力的热点来源。".to_string(),
                action_type: "add_rule".to_string(),
                rule_suggestion_key: Some("auto_temp_block_top_source".to_string()),
            });
        }
    }

    if summary.current.slow_attack_pressure_percent >= 1.0 {
        findings.push(AiAuditReportFinding {
            key: "slow_attack_present".to_string(),
            severity: "medium".to_string(),
            title: "慢速攻击信号持续存在".to_string(),
            detail: format!(
                "slow attack pressure 为 {:.2}%，说明慢头/慢体/慢握手事件持续出现。",
                summary.current.slow_attack_pressure_percent
            ),
            evidence: vec![format!(
                "slow_attack_hits={}",
                summary.counters.slow_attack_hits
            )],
        });
        recommendations.push(AiAuditReportRecommendation {
            key: "tighten_slow_attack_review".to_string(),
            priority: "medium".to_string(),
            title: "复核慢速攻击容忍窗口".to_string(),
            action: "结合 recent_events 和 top_source_ips，确认是否需要进一步收紧慢速攻击阈值或 keepalive 容忍度。".to_string(),
            rationale: "慢速攻击更容易拖垮连接资源，且在 CDN 场景下更需要结合身份态审计。".to_string(),
            action_type: "tune_threshold".to_string(),
            rule_suggestion_key: Some("tighten_slow_attack_window".to_string()),
        });
        suggested_local_rules.push(AiAuditSuggestedRuleResponse {
            key: "tighten_slow_attack_window".to_string(),
            title: "收紧慢速攻击窗口".to_string(),
            policy_type: "increase_delay".to_string(),
            layer: "l4".to_string(),
            scope_type: "source_ip".to_string(),
            scope_value: summary
                .top_source_ips
                .first()
                .map(|item| item.key.clone())
                .unwrap_or_else(|| "0.0.0.0".to_string()),
            target: "slow_attack_window".to_string(),
            action: "increase_delay".to_string(),
            operator: "decrease_threshold".to_string(),
            suggested_value: "350".to_string(),
            ttl_secs: 900,
            auto_apply: true,
            rationale: "慢头和慢体事件持续出现时，应降低容忍窗口并强化短连接降级。".to_string(),
        });
    }

    if summary.counters.l4_request_budget_softened > 0 {
        findings.push(AiAuditReportFinding {
            key: "l4_request_softening_active".to_string(),
            severity: "medium".to_string(),
            title: "L4 请求级软化正在生效".to_string(),
            detail: format!(
                "最近窗口里有 {} 次请求被 L4 请求桶软化为短连接降级，而不是直接拒绝。",
                summary.counters.l4_request_budget_softened
            ),
            evidence: vec![
                format!(
                    "l4_request_budget_softened={}",
                    summary.counters.l4_request_budget_softened
                ),
                format!(
                    "l4_bucket_budget_rejections={}",
                    summary.counters.l4_bucket_budget_rejections
                ),
            ],
        });
        recommendations.push(AiAuditReportRecommendation {
            key: "review_l4_request_softening".to_string(),
            priority: "medium".to_string(),
            title: "复核请求级软化是否持续升高".to_string(),
            action: "关注 /admin/intelligence 的 AI 审计对比视图，确认软化次数是否持续放大，并结合热点路由与身份压力判断是否需要继续优化。".to_string(),
            rationale: "请求级软化说明系统在保护可用性，如果长期升高，通常意味着热点流量或身份链路仍有持续压力。".to_string(),
            action_type: "observe".to_string(),
            rule_suggestion_key: None,
        });
    }

    if summary.current.auto_tuning_last_adjust_reason.is_some() {
        executive_summary.push(format!(
            "自动调优最近一次原因为 {:?}，当前控制器状态为 {}。",
            summary.current.auto_tuning_last_adjust_reason,
            summary.current.auto_tuning_controller_state
        ));
    }
    if let Some(top_signal) = summary.primary_signals.first() {
        executive_summary.push(format!(
            "最近窗口主导信号为 {}，命中 {} 次。",
            top_signal.key, top_signal.count
        ));
    }
    if !summary.safeline_correlation.overlap_hosts.is_empty()
        || !summary.safeline_correlation.overlap_routes.is_empty()
    {
        executive_summary.push(format!(
            "雷池事件 {} 条，Rust 事件 {} 条，共同热点 host {} 个、route {} 个。",
            summary.safeline_correlation.safeline_events,
            summary.safeline_correlation.rust_events,
            summary.safeline_correlation.overlap_hosts.len(),
            summary.safeline_correlation.overlap_routes.len()
        ));
    }
    if !summary
        .safeline_correlation
        .persistent_overlap_hosts
        .is_empty()
        || !summary
            .safeline_correlation
            .persistent_overlap_routes
            .is_empty()
    {
        executive_summary.push(format!(
            "雷池后持续压力约为 {:.1}%，未回落热点 host {} 个、route {} 个。",
            summary.safeline_correlation.rust_persistence_percent,
            summary.safeline_correlation.persistent_overlap_hosts.len(),
            summary.safeline_correlation.persistent_overlap_routes.len()
        ));
    }
    if let Some(top_identity) = summary.identity_states.first() {
        executive_summary.push(format!(
            "最近窗口最常见身份态为 {}，命中 {} 次。",
            top_identity.key, top_identity.count
        ));
    }
    if executive_summary.is_empty() {
        executive_summary.push("当前窗口未发现明显高风险聚合信号，建议继续观察。".to_string());
    }

    if recommendations.is_empty() {
        recommendations.push(AiAuditReportRecommendation {
            key: "continue_monitoring".to_string(),
            priority: "low".to_string(),
            title: "继续观察当前流量窗口".to_string(),
            action: "保持现有自动防护配置，并持续采样新的审计摘要。".to_string(),
            rationale: "当前未发现需要立即介入的强烈异常。".to_string(),
            action_type: "observe".to_string(),
            rule_suggestion_key: None,
        });
    }

    if low_confidence_input {
        for rule in &mut suggested_local_rules {
            rule.auto_apply = false;
        }
    }

    let risk_level = if findings.iter().any(|item| item.severity == "high") {
        "high"
    } else if findings.iter().any(|item| item.severity == "medium") {
        "medium"
    } else {
        "low"
    };
    let headline = match risk_level {
        "high" => "检测到需要优先排查的高风险审计信号",
        "medium" => "检测到可持续观察的中风险审计信号",
        _ => "当前窗口整体风险较低",
    }
    .to_string();

    AiAuditReportResponse {
        report_id: None,
        generated_at: summary.generated_at,
        runtime_pressure_level: summary.runtime_pressure_level.clone(),
        degraded_reasons: summary.degraded_reasons.clone(),
        provider_used: "local_rules".to_string(),
        fallback_used: false,
        analysis_mode: "analysis_only".to_string(),
        execution_notes: vec!["report generated by built-in local rules engine".to_string()],
        risk_level: risk_level.to_string(),
        headline,
        executive_summary,
        input_profile: AiAuditInputProfileResponse {
            source: "cc_behavior_joint_summary".to_string(),
            sampled_events: summary.sampled_events,
            included_recent_events: summary.recent_events.len() as u32,
            raw_samples_included: true,
            recent_policy_feedback_count: summary.recent_policy_feedback.len() as u32,
        },
        findings,
        recommendations,
        suggested_local_rules,
        summary,
    }
}

async fn apply_ai_temp_policies_from_report(
    store: &crate::storage::SqliteStore,
    report_id: Option<i64>,
    report: &AiAuditReportResponse,
    ai_config: &crate::config::AiAuditConfig,
) -> anyhow::Result<usize> {
    if report.summary.data_quality.analysis_confidence == "low" {
        return Ok(0);
    }
    let now = unix_timestamp();
    let mut applied = 0usize;
    let active_count = store.list_active_ai_temp_policies(now).await?.len() as u32;
    let confidence = match report.risk_level.as_str() {
        "critical" => 95,
        "high" => 85,
        "medium" => 70,
        _ => 55,
    };
    if active_count >= ai_config.max_active_temp_policies {
        return Ok(0);
    }
    for item in &report.suggested_local_rules {
        if !item.auto_apply {
            continue;
        }
        if confidence < ai_config.auto_apply_min_confidence as i64 {
            continue;
        }
        if item.action == "add_temp_block" && !ai_config.allow_auto_temp_block {
            continue;
        }
        if (active_count + applied as u32) >= ai_config.max_active_temp_policies {
            break;
        }
        let ttl_secs = if item.action == "add_temp_block" {
            item.ttl_secs.max(ai_config.temp_block_ttl_secs)
        } else {
            item.ttl_secs.max(ai_config.temp_policy_ttl_secs)
        };
        store
            .upsert_ai_temp_policy(&crate::storage::AiTempPolicyUpsert {
                source_report_id: report_id,
                policy_key: item.key.clone(),
                title: item.title.clone(),
                policy_type: item.policy_type.clone(),
                layer: item.layer.clone(),
                scope_type: item.scope_type.clone(),
                scope_value: item.scope_value.clone(),
                action: item.action.clone(),
                operator: item.operator.clone(),
                suggested_value: item.suggested_value.clone(),
                rationale: item.rationale.clone(),
                confidence,
                auto_applied: true,
                expires_at: now.saturating_add(ttl_secs as i64),
                effect_stats: Some(crate::storage::AiTempPolicyEffectStats {
                    baseline_l7_friction_percent: Some(
                        report.summary.current.l7_friction_pressure_percent,
                    ),
                    baseline_identity_pressure_percent: Some(
                        report.summary.current.identity_pressure_percent,
                    ),
                    baseline_rust_persistence_percent: Some(
                        report.summary.safeline_correlation.rust_persistence_percent,
                    ),
                    ..crate::storage::AiTempPolicyEffectStats::default()
                }),
            })
            .await?;
        applied += 1;
    }
    Ok(applied)
}

fn ai_temp_policy_response_from_entry(
    value: crate::storage::AiTempPolicyEntry,
    summary: &AiAuditSummaryResponse,
) -> AiTempPolicyResponse {
    let effect =
        serde_json::from_str::<crate::storage::AiTempPolicyEffectStats>(&value.effect_json)
            .unwrap_or_default();
    let l7_friction_delta = effect
        .baseline_l7_friction_percent
        .map(|value| summary.current.l7_friction_pressure_percent - value);
    let identity_pressure_delta = effect
        .baseline_identity_pressure_percent
        .map(|value| summary.current.identity_pressure_percent - value);
    let rust_persistence_delta = effect
        .baseline_rust_persistence_percent
        .map(|value| summary.safeline_correlation.rust_persistence_percent - value);
    let (action_status, action_reason, governance_hint) = classify_ai_temp_policy_action(
        value.action.as_str(),
        value.hit_count,
        l7_friction_delta,
        identity_pressure_delta,
        rust_persistence_delta,
    );
    let (primary_object, primary_object_hits) = top_effect_object(&effect);

    AiTempPolicyResponse {
        id: value.id,
        created_at: value.created_at,
        updated_at: value.updated_at,
        expires_at: value.expires_at,
        policy_key: value.policy_key,
        title: value.title,
        policy_type: value.policy_type,
        layer: value.layer,
        scope_type: value.scope_type,
        scope_value: value.scope_value,
        action: value.action,
        operator: value.operator,
        suggested_value: value.suggested_value,
        rationale: value.rationale,
        confidence: value.confidence,
        auto_applied: value.auto_applied,
        hit_count: value.hit_count,
        last_hit_at: value.last_hit_at,
        effect: AiTempPolicyEffectResponse {
            baseline_l7_friction_percent: effect.baseline_l7_friction_percent,
            baseline_identity_pressure_percent: effect.baseline_identity_pressure_percent,
            baseline_rust_persistence_percent: effect.baseline_rust_persistence_percent,
            auto_extensions: effect.auto_extensions,
            auto_revoked: effect.auto_revoked,
            auto_revoke_reason: effect.auto_revoke_reason,
            last_effectiveness_check_at: effect.last_effectiveness_check_at,
            total_hits: effect.total_hits,
            first_hit_at: effect.first_hit_at,
            last_hit_at: effect.last_hit_at,
            last_scope_type: effect.last_scope_type,
            last_scope_value: effect.last_scope_value,
            last_matched_value: effect.last_matched_value,
            last_match_mode: effect.last_match_mode,
            action_hits: effect.action_hits,
            match_modes: effect.match_modes,
            scope_hits: effect.scope_hits,
            matched_value_hits: effect.matched_value_hits,
        },
        effectiveness: AiTempPolicyEffectivenessResponse {
            current_l7_friction_percent: summary.current.l7_friction_pressure_percent,
            current_identity_pressure_percent: summary.current.identity_pressure_percent,
            current_rust_persistence_percent: summary.safeline_correlation.rust_persistence_percent,
            l7_friction_delta,
            identity_pressure_delta,
            rust_persistence_delta,
            action_status,
            action_reason,
            governance_hint,
            primary_object,
            primary_object_hits,
        },
    }
}

fn top_effect_object(effect: &crate::storage::AiTempPolicyEffectStats) -> (Option<String>, i64) {
    effect
        .matched_value_hits
        .iter()
        .max_by(|left, right| left.1.cmp(right.1).then_with(|| right.0.cmp(left.0)))
        .map(|(key, value)| (Some(key.clone()), *value))
        .unwrap_or((effect.last_matched_value.clone(), 0))
}

fn ai_audit_policy_feedback_from_entry(
    value: crate::storage::AiTempPolicyEntry,
) -> AiAuditPolicyFeedbackResponse {
    let effect =
        serde_json::from_str::<crate::storage::AiTempPolicyEffectStats>(&value.effect_json)
            .unwrap_or_default();
    let (action_status, action_reason, _) =
        classify_ai_temp_policy_action(value.action.as_str(), value.hit_count, None, None, None);
    let (primary_object, primary_object_hits) = top_effect_object(&effect);
    AiAuditPolicyFeedbackResponse {
        policy_key: value.policy_key,
        title: value.title,
        action: value.action,
        scope_type: value.scope_type,
        scope_value: value.scope_value,
        action_status,
        action_reason,
        primary_object,
        primary_object_hits,
        hit_count: value.hit_count,
        updated_at: value.updated_at,
    }
}

fn classify_ai_temp_policy_action(
    action: &str,
    hit_count: i64,
    l7_friction_delta: Option<f64>,
    identity_pressure_delta: Option<f64>,
    rust_persistence_delta: Option<f64>,
) -> (String, String, String) {
    let l7_improved = l7_friction_delta
        .map(|value| value <= -3.0)
        .unwrap_or(false);
    let identity_improved = identity_pressure_delta
        .map(|value| value <= -1.5)
        .unwrap_or(false);
    let persistence_improved = rust_persistence_delta
        .map(|value| value <= -10.0)
        .unwrap_or(false);

    match action {
        "increase_delay" => {
            if hit_count >= 3 && persistence_improved {
                (
                    "effective".to_string(),
                    "延迟策略已命中且雷池后持续压力明显回落。".to_string(),
                    "可短期续期，继续观察是否仍需升级为更强动作。".to_string(),
                )
            } else if hit_count == 0 {
                (
                    "cold".to_string(),
                    "延迟策略尚未命中，暂时无法说明对热点有真实覆盖。".to_string(),
                    "热身后若仍无命中，可优先清退。".to_string(),
                )
            } else {
                (
                    "watch".to_string(),
                    "延迟策略已有命中，但持续压力回落还不够明显。".to_string(),
                    "继续观察持续压力与命中数，必要时升级 challenge 或 route 收紧。".to_string(),
                )
            }
        }
        "tighten_route_cc" | "tighten_host_cc" | "increase_challenge" => {
            if hit_count >= 2 && l7_improved {
                (
                    "effective".to_string(),
                    "摩擦类策略已命中，并且 L7 摩擦压力相对基线下降。".to_string(),
                    "可有限续期，优先保持热点对象的短期收紧。".to_string(),
                )
            } else if hit_count == 0 {
                (
                    "cold".to_string(),
                    "摩擦类策略尚未命中，说明当前覆盖面可能偏窄。".to_string(),
                    "热身后若无命中，可考虑撤销或改用更合适的匹配范围。".to_string(),
                )
            } else {
                (
                    "watch".to_string(),
                    "摩擦类策略已有命中，但 L7 压力改善仍不充分。".to_string(),
                    "继续观察，若压力不降可升级为短时 block 或更严阈值。".to_string(),
                )
            }
        }
        "raise_identity_risk" | "add_behavior_watch" => {
            if hit_count >= 2 && identity_improved {
                (
                    "effective".to_string(),
                    "行为/身份策略已命中，并且身份压力相对基线回落。".to_string(),
                    "可短期保留，继续观察是否还有未解析身份回流。".to_string(),
                )
            } else if hit_count == 0 {
                (
                    "cold".to_string(),
                    "行为/身份策略尚未命中，当前无法证明其作用范围有效。".to_string(),
                    "若热身后仍无命中，应优先清退。".to_string(),
                )
            } else {
                (
                    "watch".to_string(),
                    "行为/身份策略已有命中，但身份压力改善不明显。".to_string(),
                    "继续观察，必要时结合真实 IP 链路或热点对象再收紧。".to_string(),
                )
            }
        }
        "add_temp_block" => {
            if hit_count >= 1 && persistence_improved {
                (
                    "effective".to_string(),
                    "临时封禁已命中，且雷池后持续压力明显下降。".to_string(),
                    "仅建议短时续期，避免过度阻断。".to_string(),
                )
            } else if hit_count == 0 {
                (
                    "cold".to_string(),
                    "临时封禁尚未命中，当前无法证明封禁对象仍然活跃。".to_string(),
                    "热身后若仍无命中，可自动退出。".to_string(),
                )
            } else {
                (
                    "watch".to_string(),
                    "临时封禁已有命中，但持续压力仍未明显下降。".to_string(),
                    "继续观察，必要时扩大匹配范围或转为 route 级策略。".to_string(),
                )
            }
        }
        _ => (
            "watch".to_string(),
            "当前策略动作缺少专项评估模型，先按通用观察处理。".to_string(),
            "建议结合命中和压力变化手动复核。".to_string(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_summary() -> AiAuditSummaryResponse {
        AiAuditSummaryResponse {
            generated_at: 1,
            window_seconds: 3600,
            sampled_events: 10,
            total_events: 10,
            active_rules: 5,
            runtime_pressure_level: "high".to_string(),
            degraded_reasons: vec![
                "management_ai_audit_sample_reduced_under_runtime_pressure".to_string()
            ],
            data_quality: AiAuditDataQualityResponse {
                persisted_security_events: 100,
                dropped_security_events: 0,
                sqlite_queue_depth: 4,
                sqlite_queue_capacity: 128,
                sqlite_queue_usage_percent: 3.1,
                detail_slimming_active: false,
                sample_coverage_ratio: 1.0,
                persistence_coverage_ratio: 1.0,
                raw_samples_included: true,
                recent_events_count: 0,
                analysis_confidence: "high".to_string(),
            },
            current: AiAuditCurrentStateResponse {
                adaptive_system_pressure: "elevated".to_string(),
                adaptive_reasons: vec!["identity_resolution_pressure".to_string()],
                l4_overload_level: "high".to_string(),
                auto_tuning_controller_state: "adjusted".to_string(),
                auto_tuning_last_adjust_reason: Some(
                    "adjust_for_identity_resolution_pressure".to_string(),
                ),
                auto_tuning_last_adjust_diff: vec!["l4 budget tightened".to_string()],
                identity_pressure_percent: 6.2,
                l7_friction_pressure_percent: 24.0,
                slow_attack_pressure_percent: 1.2,
            },
            counters: AiAuditCountersResponse {
                proxied_requests: 100,
                blocked_packets: 20,
                blocked_l4: 3,
                blocked_l7: 17,
                l7_cc_challenges: 12,
                l7_cc_blocks: 6,
                l7_cc_delays: 8,
                l7_behavior_challenges: 4,
                l7_behavior_blocks: 3,
                l7_behavior_delays: 5,
                l4_bucket_budget_rejections: 2,
                trusted_proxy_permit_drops: 9,
                trusted_proxy_l4_degrade_actions: 7,
                l4_request_budget_softened: 4,
                slow_attack_hits: 4,
                average_proxy_latency_micros: 12_000,
            },
            action_breakdown: vec![AiAuditCountItem {
                key: "block".to_string(),
                count: 4,
            }],
            provider_breakdown: vec![AiAuditCountItem {
                key: "local".to_string(),
                count: 10,
            }],
            identity_states: vec![AiAuditCountItem {
                key: "trusted_cdn_unresolved".to_string(),
                count: 6,
            }],
            primary_signals: vec![AiAuditCountItem {
                key: "l7_cc:block".to_string(),
                count: 4,
            }],
            labels: vec![AiAuditCountItem {
                key: "identity:trusted_cdn_unresolved".to_string(),
                count: 6,
            }],
            top_source_ips: Vec::new(),
            top_routes: Vec::new(),
            top_hosts: Vec::new(),
            safeline_correlation: AiAuditSafeLineCorrelationResponse::default(),
            trend_windows: vec![AiAuditTrendWindowResponse {
                label: "last_5m".to_string(),
                window_seconds: 300,
                total_events: 4,
                sampled_events: 4,
                blocked_events: 2,
                challenged_events: 1,
                delayed_events: 1,
                action_breakdown: Vec::new(),
                top_source_ips: Vec::new(),
                top_routes: Vec::new(),
                top_hosts: Vec::new(),
            }],
            recent_policy_feedback: Vec::new(),
            recent_events: Vec::new(),
        }
    }

    #[test]
    fn ai_audit_report_promotes_high_risk_findings() {
        let report = build_ai_audit_report(base_summary());

        assert_eq!(report.risk_level, "high");
        assert!(!report.findings.is_empty());
        assert!(report
            .recommendations
            .iter()
            .any(|item| item.key == "review_real_ip_chain"));
    }

    #[test]
    fn ai_audit_report_falls_back_to_monitoring_when_quiet() {
        let mut summary = base_summary();
        summary.current.identity_pressure_percent = 0.0;
        summary.current.l7_friction_pressure_percent = 0.0;
        summary.current.slow_attack_pressure_percent = 0.0;
        summary.current.auto_tuning_last_adjust_reason = None;
        summary.counters.l4_bucket_budget_rejections = 0;
        summary.counters.trusted_proxy_permit_drops = 0;
        summary.counters.trusted_proxy_l4_degrade_actions = 0;
        summary.counters.l4_request_budget_softened = 0;
        summary.identity_states.clear();
        summary.primary_signals.clear();
        let report = build_ai_audit_report(summary);

        assert_eq!(report.risk_level, "low");
        assert!(report.findings.is_empty());
        assert_eq!(report.recommendations.len(), 1);
        assert_eq!(report.recommendations[0].key, "continue_monitoring");
    }

    #[test]
    fn ai_audit_report_emits_safeline_overlap_recommendation() {
        let mut summary = base_summary();
        summary.safeline_correlation = AiAuditSafeLineCorrelationResponse {
            safeline_events: 8,
            rust_events: 12,
            rust_persistence_percent: 150.0,
            safeline_top_hosts: vec![AiAuditCountItem {
                key: "api.example.com".to_string(),
                count: 6,
            }],
            rust_top_hosts: vec![AiAuditCountItem {
                key: "api.example.com".to_string(),
                count: 5,
            }],
            overlap_hosts: vec![AiAuditCountItem {
                key: "api.example.com".to_string(),
                count: 5,
            }],
            overlap_routes: vec![AiAuditCountItem {
                key: "/login".to_string(),
                count: 4,
            }],
            overlap_source_ips: vec![AiAuditCountItem {
                key: "203.0.113.10".to_string(),
                count: 3,
            }],
            persistent_overlap_hosts: vec![AiAuditCountItem {
                key: "api.example.com".to_string(),
                count: 2,
            }],
            persistent_overlap_routes: vec![AiAuditCountItem {
                key: "/login".to_string(),
                count: 2,
            }],
            persistent_overlap_source_ips: vec![AiAuditCountItem {
                key: "203.0.113.10".to_string(),
                count: 1,
            }],
        };

        let report = build_ai_audit_report(summary);

        assert!(report
            .findings
            .iter()
            .any(|item| item.key == "safeline_rust_overlap_detected"));
        assert!(report
            .suggested_local_rules
            .iter()
            .any(|item| item.key == "tighten_safeline_overlap_route"));
        assert!(report
            .suggested_local_rules
            .iter()
            .any(|item| item.key == "raise_post_safeline_friction"));
    }

    #[test]
    fn ai_audit_report_disables_auto_apply_when_input_confidence_is_low() {
        let mut summary = base_summary();
        summary.data_quality.analysis_confidence = "low".to_string();
        summary.data_quality.dropped_security_events = 8;
        summary.safeline_correlation.overlap_routes = vec![AiAuditCountItem {
            key: "/login".to_string(),
            count: 3,
        }];

        let report = build_ai_audit_report(summary);

        assert!(report
            .recommendations
            .iter()
            .any(|item| item.key == "manual_review_due_to_degraded_input"));
        assert!(report.suggested_local_rules.iter().all(|item| !item.auto_apply));
    }

    #[test]
    fn scaled_limit_preserves_minimum_floor() {
        assert_eq!(scaled_limit(100, 2, 20), 50);
        assert_eq!(scaled_limit(30, 4, 20), 20);
        assert_eq!(scaled_limit(0, 4, 0), 0);
    }
}
