pub(super) fn ai_defense_runtime_pressure_response(
    value: crate::core::AiDefenseRuntimePressureSignal,
) -> AiDefenseRuntimePressureResponse {
    AiDefenseRuntimePressureResponse {
        level: value.level,
        defense_depth: value.defense_depth,
        prefer_drop: value.prefer_drop,
        trim_event_persistence: value.trim_event_persistence,
        l7_friction_pressure_percent: value.l7_friction_pressure_percent,
        identity_pressure_percent: value.identity_pressure_percent,
        avg_proxy_latency_ms: value.avg_proxy_latency_ms,
    }
}

pub(super) fn ai_defense_l4_pressure_response(
    value: crate::core::AiDefenseL4Signal,
) -> AiDefenseL4PressureResponse {
    AiDefenseL4PressureResponse {
        active_connections: value.active_connections,
        blocked_connections: value.blocked_connections,
        rate_limit_hits: value.rate_limit_hits,
        ddos_events: value.ddos_events,
        protocol_anomalies: value.protocol_anomalies,
        defense_actions: value.defense_actions,
        top_ports: value
            .top_ports
            .into_iter()
            .map(|port| AiDefensePortResponse {
                port: port.port,
                connections: port.connections,
                blocks: port.blocks,
                ddos_events: port.ddos_events,
            })
            .collect(),
    }
}

pub(super) fn ai_defense_route_effect_response(
    value: crate::core::AiDefenseRouteEffectSignal,
) -> AiDefenseRouteEffectResponse {
    AiDefenseRouteEffectResponse {
        site_id: value.site_id,
        route: value.route,
        total_responses: value.total_responses,
        upstream_successes: value.upstream_successes,
        upstream_errors: value.upstream_errors,
        local_responses: value.local_responses,
        blocked_responses: value.blocked_responses,
        challenge_issued: value.challenge_issued,
        challenge_verified: value.challenge_verified,
        interactive_sessions: value.interactive_sessions,
        policy_matched_responses: value.policy_matched_responses,
        suspected_false_positive_events: value.suspected_false_positive_events,
        status_families: value.status_families,
        status_codes: value.status_codes,
        policy_actions: value.policy_actions,
        avg_latency_ms: value.avg_latency_ms,
        slow_responses: value.slow_responses,
        false_positive_risk: value.false_positive_risk,
        effectiveness_hint: value.effectiveness_hint,
    }
}

pub(super) fn ai_defense_policy_effect_response(
    value: crate::core::AiDefensePolicyEffectSignal,
) -> AiDefensePolicyEffectResponse {
    AiDefensePolicyEffectResponse {
        policy_key: value.policy_key,
        scope_type: value.scope_type,
        scope_value: value.scope_value,
        action: value.action,
        hit_count: value.hit_count,
        outcome_status: value.outcome_status,
        outcome_score: value.outcome_score,
        observations: value.observations,
        upstream_errors: value.upstream_errors,
        suspected_false_positive_events: value.suspected_false_positive_events,
        challenge_verified: value.challenge_verified,
        pressure_after_observations: value.pressure_after_observations,
    }
}

pub(super) fn ai_defense_identity_response(
    value: crate::core::AiDefenseIdentitySignal,
) -> AiDefenseIdentityResponse {
    AiDefenseIdentityResponse {
        site_id: value.site_id,
        route: value.route,
        total_events: value.total_events,
        distinct_client_count: value.distinct_client_count,
        unresolved_events: value.unresolved_events,
        trusted_proxy_events: value.trusted_proxy_events,
        verified_challenge_events: value.verified_challenge_events,
        interactive_session_events: value.interactive_session_events,
        spoofed_forward_header_events: value.spoofed_forward_header_events,
        top_user_agents: value
            .top_user_agents
            .into_iter()
            .map(|item| AiDefenseUserAgentResponse {
                value: item.value,
                count: item.count,
            })
            .collect(),
    }
}

pub(super) fn ai_defense_route_profile_signal_response(
    value: crate::core::AiDefenseRouteProfileSignal,
) -> AiDefenseRouteProfileSignalResponse {
    AiDefenseRouteProfileSignalResponse {
        site_id: value.site_id,
        route_pattern: value.route_pattern,
        match_mode: value.match_mode,
        route_type: value.route_type,
        sensitivity: value.sensitivity,
        auth_required: value.auth_required,
        normal_traffic_pattern: value.normal_traffic_pattern,
        recommended_actions: value.recommended_actions,
        avoid_actions: value.avoid_actions,
        evidence: value.evidence,
        raw_confidence: value.raw_confidence,
        staleness_secs: value.staleness_secs,
        confidence: value.confidence,
        source: value.source,
        status: value.status,
        rationale: value.rationale,
    }
}

pub(super) fn visitor_intelligence_response(
    value: crate::core::VisitorIntelligenceSnapshot,
) -> AiVisitorIntelligenceResponse {
    AiVisitorIntelligenceResponse {
        generated_at: value.generated_at,
        enabled: value.enabled,
        degraded_reason: value.degraded_reason,
        active_profile_count: value.active_profile_count,
        profiles: value
            .profiles
            .into_iter()
            .map(visitor_profile_signal_response)
            .collect(),
        recommendations: value
            .recommendations
            .into_iter()
            .map(visitor_decision_signal_response)
            .collect(),
    }
}

fn visitor_profile_signal_response(
    value: crate::core::VisitorProfileSignal,
) -> AiVisitorProfileSignalResponse {
    AiVisitorProfileSignalResponse {
        identity_key: value.identity_key,
        identity_source: value.identity_source,
        site_id: value.site_id,
        client_ip: value.client_ip,
        user_agent: value.user_agent,
        state: value.state,
        first_seen_at: value.first_seen_at,
        last_seen_at: value.last_seen_at,
        request_count: value.request_count,
        document_count: value.document_count,
        api_count: value.api_count,
        static_count: value.static_count,
        admin_count: value.admin_count,
        challenge_count: value.challenge_count,
        challenge_verified_count: value.challenge_verified_count,
        challenge_page_report_count: value.challenge_page_report_count,
        challenge_js_report_count: value.challenge_js_report_count,
        fingerprint_seen: value.fingerprint_seen,
        upstream_success_count: value.upstream_success_count,
        upstream_redirect_count: value.upstream_redirect_count,
        upstream_client_error_count: value.upstream_client_error_count,
        upstream_error_count: value.upstream_error_count,
        auth_required_route_count: value.auth_required_route_count,
        auth_success_count: value.auth_success_count,
        auth_rejected_count: value.auth_rejected_count,
        human_confidence: value.human_confidence,
        automation_risk: value.automation_risk,
        probe_risk: value.probe_risk,
        abuse_risk: value.abuse_risk,
        false_positive_risk: value.false_positive_risk,
        tracking_priority: value.tracking_priority,
        route_summary: value
            .route_summary
            .into_iter()
            .map(|item| AiVisitorRouteSummaryResponse {
                route: item.route,
                count: item.count,
            })
            .collect(),
        business_route_types: value.business_route_types,
        status_codes: value.status_codes,
        flags: value.flags,
        ai_rationale: value.ai_rationale,
    }
}

fn visitor_decision_signal_response(
    value: crate::core::VisitorDecisionSignal,
) -> AiVisitorDecisionSignalResponse {
    AiVisitorDecisionSignalResponse {
        decision_key: value.decision_key,
        identity_key: value.identity_key,
        site_id: value.site_id,
        action: value.action,
        confidence: value.confidence,
        ttl_secs: value.ttl_secs,
        rationale: value.rationale,
        applied: value.applied,
        effect_status: value.effect_status,
    }
}
pub(super) fn local_defense_recommendation_response(
    item: crate::core::LocalDefenseRecommendation,
) -> LocalDefenseRecommendationResponse {
    let title = format!("Tighten route CC for {}", item.route);
    LocalDefenseRecommendationResponse {
        key: item.key.clone(),
        title: title.clone(),
        site_id: item.site_id.clone(),
        route: item.route.clone(),
        defense_depth: item.defense_depth.clone(),
        soft_events: item.soft_events,
        hard_events: item.hard_events,
        total_events: item.total_events,
        confidence: item.confidence,
        suggested_rule: AiAuditSuggestedRuleResponse {
            key: item.key,
            title,
            policy_type: "tighten_route_cc".to_string(),
            layer: "L7".to_string(),
            scope_type: "route".to_string(),
            scope_value: item.route,
            target: format!("site:{}", item.site_id),
            action: item.action,
            operator: "exact".to_string(),
            suggested_value: item.suggested_value,
            ttl_secs: item.ttl_secs,
            auto_apply: false,
            rationale: item.rationale,
        },
    }
}
use super::*;
