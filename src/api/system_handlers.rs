use super::*;
use std::collections::BTreeMap;

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
    ))
}

pub(super) async fn traffic_map_handler(
    State(state): State<ApiState>,
    Query(params): Query<TrafficMapQueryParams>,
) -> Json<TrafficMapResponse> {
    let snapshot = state
        .context
        .traffic_map_snapshot(params.window_seconds.unwrap_or(60))
        .await;

    Json(TrafficMapResponse {
        scope: snapshot.scope,
        window_seconds: snapshot.window_seconds,
        generated_at: snapshot.generated_at,
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
    Query(params): Query<AiAuditReportQueryParams>,
) -> ApiResult<Json<AiAuditReportResponse>> {
    let provider = crate::api::ai_audit::provider_from_report_query(&params);
    let summary_query = crate::api::ai_audit::summary_query_from_report(&params);
    let summary = build_ai_audit_summary(
        &state,
        summary_query.window_seconds,
        summary_query.sample_limit,
        summary_query.recent_limit,
    )
    .await?;
    Ok(Json(crate::api::ai_audit::finalize_report_execution(
        provider,
        params.fallback_to_rules.unwrap_or(true),
        summary,
        build_ai_audit_report,
    )))
}

async fn build_ai_audit_summary(
    state: &ApiState,
    window_seconds: Option<u32>,
    sample_limit: Option<u32>,
    recent_limit: Option<u32>,
) -> ApiResult<AiAuditSummaryResponse> {
    let store = sqlite_store(&state)?;
    let now = unix_timestamp();
    let window_seconds = window_seconds.unwrap_or(3600).clamp(60, 24 * 3600);
    let sample_limit = sample_limit.unwrap_or(200).clamp(20, 1000);
    let recent_limit = recent_limit.unwrap_or(20).clamp(5, 100);
    let created_from = now.saturating_sub(window_seconds as i64);

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

    let metrics = state.context.metrics_snapshot().unwrap_or_default();
    let auto = state.context.auto_tuning_snapshot();
    let adaptive = state.context.adaptive_protection_snapshot();

    let mut identity_states = BTreeMap::new();
    let mut primary_signals = BTreeMap::new();
    let mut labels = BTreeMap::new();
    let mut top_source_ips = BTreeMap::new();
    let mut top_routes = BTreeMap::new();
    let mut top_hosts = BTreeMap::new();

    let sampled_events = result.items.len() as u32;
    let mut recent_events = Vec::new();

    for event in result.items.into_iter().map(SecurityEventResponse::from) {
        if recent_events.len() < recent_limit as usize {
            recent_events.push(AiAuditEventSampleResponse::from(event.clone()));
        }
        increment_map(&mut top_source_ips, &event.source_ip);
        if let Some(uri) = event.uri.as_deref() {
            increment_map(&mut top_routes, uri);
        }
        if let Some(host) = event.provider_site_domain.as_deref() {
            increment_map(&mut top_hosts, host);
        }
        if let Some(summary) = event.decision_summary.as_ref() {
            if let Some(identity_state) = summary.identity_state.as_deref() {
                increment_map(&mut identity_states, identity_state);
            }
            increment_map(&mut primary_signals, &summary.primary_signal);
            for label in &summary.labels {
                increment_map(&mut labels, label);
            }
        }
    }

    Ok(AiAuditSummaryResponse {
        generated_at: now,
        window_seconds,
        sampled_events,
        total_events: result.total,
        active_rules: state.context.active_rule_count(),
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
            trusted_proxy_permit_drops: metrics.trusted_proxy_permit_drops,
            trusted_proxy_l4_degrade_actions: metrics.trusted_proxy_l4_degrade_actions,
            slow_attack_hits: metrics.slow_attack_idle_timeouts
                + metrics.slow_attack_header_timeouts
                + metrics.slow_attack_body_timeouts
                + metrics.slow_attack_tls_handshake_hits
                + metrics.slow_attack_blocks,
            average_proxy_latency_micros: metrics.average_proxy_latency_micros,
        },
        identity_states: top_count_items(identity_states, 8),
        primary_signals: top_count_items(primary_signals, 8),
        labels: top_count_items(labels, 12),
        top_source_ips: top_count_items(top_source_ips, 8),
        top_routes: top_count_items(top_routes, 8),
        top_hosts: top_count_items(top_hosts, 8),
        recent_events,
    })
}

fn increment_map(map: &mut BTreeMap<String, u64>, key: &str) {
    *map.entry(key.to_string()).or_insert(0) += 1;
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
    if metrics.trusted_proxy_l4_degrade_actions > 0 || metrics.l4_bucket_budget_rejections > 0 {
        "high".to_string()
    } else {
        "normal".to_string()
    }
}

fn build_ai_audit_report(summary: AiAuditSummaryResponse) -> AiAuditReportResponse {
    let mut findings = Vec::new();
    let mut recommendations = Vec::new();
    let mut executive_summary = Vec::new();

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
        });
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
        });
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
        generated_at: summary.generated_at,
        provider_used: "local_rules".to_string(),
        fallback_used: false,
        execution_notes: vec!["report generated by built-in local rules engine".to_string()],
        risk_level: risk_level.to_string(),
        headline,
        executive_summary,
        findings,
        recommendations,
        summary,
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
                trusted_proxy_permit_drops: 9,
                trusted_proxy_l4_degrade_actions: 7,
                slow_attack_hits: 4,
                average_proxy_latency_micros: 12_000,
            },
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
        summary.identity_states.clear();
        summary.primary_signals.clear();
        let report = build_ai_audit_report(summary);

        assert_eq!(report.risk_level, "low");
        assert!(report.findings.is_empty());
        assert_eq!(report.recommendations.len(), 1);
        assert_eq!(report.recommendations[0].key, "continue_monitoring");
    }
}
