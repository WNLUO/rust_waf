use super::*;

pub(super) fn build_ai_audit_report(summary: AiAuditSummaryResponse) -> AiAuditReportResponse {
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
                l7_ip_access_allows: 2,
                l7_ip_access_alerts: 1,
                l7_ip_access_challenges: 8,
                l7_ip_access_blocks: 6,
                l7_ip_access_verified_passes: 1,
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
        assert!(report
            .suggested_local_rules
            .iter()
            .all(|item| !item.auto_apply));
    }

    #[test]
    fn scaled_limit_preserves_minimum_floor() {
        assert_eq!(scaled_limit(100, 2, 20), 50);
        assert_eq!(scaled_limit(30, 4, 20), 20);
        assert_eq!(scaled_limit(0, 4, 0), 0);
    }
}
