use super::*;

pub(super) fn ai_defense_decision_from_local_recommendation(
    snapshot: &AiDefenseSignalSnapshot,
    recommendation: &LocalDefenseRecommendation,
) -> Option<AiDefenseDecision> {
    if recommendation.action != "tighten_route_cc" {
        return None;
    }
    if !ai_defense_route_allowed(&recommendation.route) {
        return None;
    }
    let mut confidence = recommendation.confidence;
    if snapshot.l4_pressure.as_ref().is_some_and(|l4| {
        l4.blocked_connections > 0 || l4.rate_limit_hits > 0 || l4.ddos_events > 0
    }) {
        confidence = confidence.saturating_add(4).min(100);
    }
    if snapshot.runtime_pressure.defense_depth == "survival" {
        confidence = confidence.saturating_add(3).min(100);
    }
    if let Some(identity) = snapshot.identity_summaries.iter().find(|identity| {
        identity.site_id == recommendation.site_id && identity.route == recommendation.route
    }) {
        if identity.distinct_client_count >= 8 && identity.interactive_session_events == 0 {
            confidence = confidence.saturating_add(5).min(100);
        }
        if identity.spoofed_forward_header_events > 0 {
            confidence = confidence.saturating_add(6).min(100);
        }
        if identity.verified_challenge_events.saturating_mul(2) >= identity.total_events
            || identity.interactive_session_events.saturating_mul(2) >= identity.total_events
        {
            confidence = confidence.saturating_sub(10);
        }
        if identity.unresolved_events.saturating_mul(2) >= identity.total_events
            && identity.distinct_client_count <= 2
        {
            confidence = confidence.saturating_sub(6);
        }
    }
    let route_profile = best_route_profile_for_recommendation(snapshot, recommendation);
    if let Some(profile) = route_profile {
        if profile
            .avoid_actions
            .iter()
            .any(|action| action == &recommendation.action)
        {
            confidence = confidence.saturating_sub(20);
        }
        if profile
            .recommended_actions
            .iter()
            .any(|action| action == &recommendation.action)
        {
            confidence = confidence.saturating_add(4).min(100);
        }
        if matches!(profile.sensitivity.as_str(), "critical" | "high") {
            confidence = confidence.saturating_add(2).min(100);
        }
    }
    let route_effect = best_route_effect_for_recommendation(snapshot, recommendation);
    if let Some(effect) = route_effect {
        match effect.false_positive_risk.as_str() {
            "high" => confidence = confidence.saturating_sub(25),
            "medium" => confidence = confidence.saturating_sub(10),
            _ => {}
        }
        if effect.upstream_errors >= 5 {
            confidence = confidence.saturating_sub(8);
        }
        if effect
            .policy_actions
            .get(&recommendation.action)
            .is_some_and(|count| *count >= 3)
            && effect.effectiveness_hint == "effective"
        {
            confidence = confidence.saturating_add(5).min(100);
        }
    }
    if let Some(policy_effect) = best_policy_effect_for_recommendation(snapshot, recommendation) {
        match policy_effect.outcome_status.as_str() {
            "effective" => confidence = confidence.saturating_add(8).min(100),
            "harmful" => confidence = confidence.saturating_sub(30),
            "neutral" => confidence = confidence.saturating_sub(4),
            _ => {}
        }
    }
    if !snapshot.upstream_health.healthy {
        confidence = confidence.saturating_sub(8);
    }

    Some(AiDefenseDecision {
        key: format!("ai_auto_defense:{}", recommendation.key),
        title: format!("AI auto defense for {}", recommendation.route),
        layer: "l7".to_string(),
        scope_type: "route".to_string(),
        scope_value: recommendation.route.clone(),
        action: recommendation.action.clone(),
        operator: "exact".to_string(),
        suggested_value: recommendation.suggested_value.clone(),
        ttl_secs: recommendation.ttl_secs,
        confidence,
        auto_apply: true,
        rationale: format!(
            "{}; auto-applied by local AI defense guardrails for site {}; trigger={}; runtime_depth={}; upstream_healthy={}; route_profile={}; effect_hint={}; false_positive_risk={}",
            recommendation.rationale,
            recommendation.site_id,
            snapshot
                .trigger_reason
                .as_deref()
                .unwrap_or("unknown"),
            snapshot.runtime_pressure.defense_depth,
            snapshot.upstream_health.healthy,
            route_profile
                .map(|profile| profile.route_type.as_str())
                .unwrap_or("unknown"),
            route_effect
                .map(|effect| effect.effectiveness_hint.as_str())
                .unwrap_or("unknown"),
            route_effect
                .map(|effect| effect.false_positive_risk.as_str())
                .unwrap_or("unknown")
        ),
    })
}

fn best_route_profile_for_recommendation<'a>(
    snapshot: &'a AiDefenseSignalSnapshot,
    recommendation: &LocalDefenseRecommendation,
) -> Option<&'a AiDefenseRouteProfileSignal> {
    snapshot
        .route_profiles
        .iter()
        .filter(|profile| {
            profile.site_id == recommendation.site_id
                && route_profile_matches(profile, &recommendation.route)
        })
        .max_by(|left, right| {
            profile_match_rank(left)
                .cmp(&profile_match_rank(right))
                .then_with(|| left.confidence.cmp(&right.confidence))
        })
}

fn best_route_effect_for_recommendation<'a>(
    snapshot: &'a AiDefenseSignalSnapshot,
    recommendation: &LocalDefenseRecommendation,
) -> Option<&'a AiDefenseRouteEffectSignal> {
    snapshot.route_effects.iter().find(|effect| {
        effect.site_id == recommendation.site_id && effect.route == recommendation.route
    })
}

fn best_policy_effect_for_recommendation<'a>(
    snapshot: &'a AiDefenseSignalSnapshot,
    recommendation: &LocalDefenseRecommendation,
) -> Option<&'a AiDefensePolicyEffectSignal> {
    snapshot.policy_effects.iter().find(|effect| {
        effect.scope_type == "route"
            && effect.scope_value == recommendation.route
            && effect.action == recommendation.action
    })
}

pub(super) fn visitor_decision_policy_action(action: &str) -> Option<(&'static str, &'static str)> {
    match action {
        "watch_visitor" => Some(("add_behavior_watch", "20")),
        "increase_challenge" => Some(("increase_challenge", "challenge")),
        "reduce_friction" | "mark_trusted_temporarily" => Some(("reduce_friction", "trusted")),
        _ => None,
    }
}

fn route_profile_matches(profile: &AiDefenseRouteProfileSignal, route: &str) -> bool {
    match profile.match_mode.as_str() {
        "prefix" | "starts_with" => route.starts_with(&profile.route_pattern),
        "wildcard" if profile.route_pattern.ends_with('*') => {
            route.starts_with(profile.route_pattern.trim_end_matches('*'))
        }
        _ => route == profile.route_pattern,
    }
}

fn profile_match_rank(profile: &AiDefenseRouteProfileSignal) -> u8 {
    match profile.match_mode.as_str() {
        "exact" => 3,
        "prefix" | "starts_with" => 2,
        "wildcard" => 1,
        _ => 0,
    }
}

pub(super) fn infer_route_profile_candidate(
    recommendation: &LocalDefenseRecommendation,
    identity: Option<&AiDefenseIdentitySignal>,
    route_effect: Option<&AiDefenseRouteEffectSignal>,
    now: i64,
    relearn_after_rejected: bool,
) -> AiRouteProfileUpsert {
    let route_lower = recommendation.route.to_ascii_lowercase();
    let mut route_type = "unknown";
    let mut sensitivity = "unknown";
    let mut auth_required = "unknown";
    let mut normal_traffic_pattern = "unknown";
    let mut recommended_actions = vec!["tighten_route_cc".to_string()];
    let mut avoid_actions = Vec::<String>::new();
    let mut confidence = 55i64;

    if route_lower.contains("login")
        || route_lower.contains("signin")
        || route_lower.contains("auth")
        || route_lower.contains("token")
        || route_lower.contains("sso")
    {
        route_type = "authentication";
        sensitivity = "high";
        auth_required = "false";
        normal_traffic_pattern = "interactive";
        recommended_actions.push("increase_challenge".to_string());
        avoid_actions.push("add_temp_block".to_string());
        confidence += 18;
    } else if route_lower.contains("callback")
        || route_lower.contains("webhook")
        || route_lower.contains("notify")
    {
        route_type = "callback";
        sensitivity = "high";
        normal_traffic_pattern = "machine_to_machine";
        avoid_actions.push("increase_challenge".to_string());
        avoid_actions.push("increase_delay".to_string());
        recommended_actions.push("raise_identity_risk".to_string());
        confidence += 14;
    } else if route_lower.starts_with("/api/")
        || route_lower.contains("/api/")
        || route_lower.contains("graphql")
    {
        route_type = "api";
        sensitivity = "medium";
        normal_traffic_pattern = "api";
        recommended_actions.push("raise_identity_risk".to_string());
        confidence += 10;
    } else if route_lower.contains("admin")
        || route_lower.contains("console")
        || route_lower.contains("dashboard")
    {
        route_type = "admin";
        sensitivity = "critical";
        auth_required = "true";
        normal_traffic_pattern = "interactive";
        recommended_actions.push("increase_challenge".to_string());
        avoid_actions.push("add_temp_block".to_string());
        confidence += 18;
    }

    if let Some(identity) = identity {
        if identity.distinct_client_count >= 8 {
            confidence += 6;
        }
        if identity.verified_challenge_events.saturating_mul(2) >= identity.total_events
            || identity.interactive_session_events.saturating_mul(2) >= identity.total_events
        {
            normal_traffic_pattern = "interactive";
            confidence += 4;
        }
        if identity.unresolved_events.saturating_mul(2) >= identity.total_events {
            auth_required = "unknown";
            confidence -= 4;
        }
    }
    if recommendation.defense_depth == "survival" {
        confidence += 6;
    }
    if relearn_after_rejected {
        confidence -= 6;
    }
    if let Some(effect) = route_effect {
        match effect.false_positive_risk.as_str() {
            "high" => {
                avoid_actions.push("add_temp_block".to_string());
                confidence -= 10;
            }
            "medium" => confidence -= 4,
            _ => {}
        }
        if effect.effectiveness_hint == "effective" {
            confidence += 4;
        }
    }

    recommended_actions.sort();
    recommended_actions.dedup();
    avoid_actions.sort();
    avoid_actions.dedup();

    let evidence_json = serde_json::json!({
        "learning_mode": if relearn_after_rejected {
            "relearn_after_rejected"
        } else {
            "observed_candidate"
        },
        "observed_at": now,
        "route_pressure": {
            "defense_depth": recommendation.defense_depth,
            "soft_events": recommendation.soft_events,
            "hard_events": recommendation.hard_events,
            "total_events": recommendation.total_events,
            "recommended_action": recommendation.action,
            "suggested_value": recommendation.suggested_value,
            "ttl_secs": recommendation.ttl_secs,
            "local_confidence": recommendation.confidence,
            "rationale": recommendation.rationale,
        },
        "identity": identity.map(|identity| serde_json::json!({
            "total_events": identity.total_events,
            "distinct_client_count": identity.distinct_client_count,
            "unresolved_events": identity.unresolved_events,
            "trusted_proxy_events": identity.trusted_proxy_events,
            "verified_challenge_events": identity.verified_challenge_events,
            "interactive_session_events": identity.interactive_session_events,
            "spoofed_forward_header_events": identity.spoofed_forward_header_events,
            "top_user_agents": identity.top_user_agents.iter().map(|ua| serde_json::json!({
                "value": &ua.value,
                "count": ua.count,
            })).collect::<Vec<_>>(),
        })),
        "route_effect": route_effect.map(|effect| serde_json::json!({
            "total_responses": effect.total_responses,
            "upstream_errors": effect.upstream_errors,
            "local_responses": effect.local_responses,
            "blocked_responses": effect.blocked_responses,
            "challenge_issued": effect.challenge_issued,
            "challenge_verified": effect.challenge_verified,
            "interactive_sessions": effect.interactive_sessions,
            "policy_matched_responses": effect.policy_matched_responses,
            "suspected_false_positive_events": effect.suspected_false_positive_events,
            "status_families": &effect.status_families,
            "status_codes": &effect.status_codes,
            "policy_actions": &effect.policy_actions,
            "avg_latency_ms": effect.avg_latency_ms,
            "slow_responses": effect.slow_responses,
            "false_positive_risk": &effect.false_positive_risk,
            "effectiveness_hint": &effect.effectiveness_hint,
        })),
        "confidence_inputs": {
            "route_name_heuristic": route_type,
            "sensitivity": sensitivity,
            "auth_required": auth_required,
            "normal_traffic_pattern": normal_traffic_pattern,
            "relearn_penalty_applied": relearn_after_rejected,
        }
    });

    AiRouteProfileUpsert {
        site_id: recommendation.site_id.clone(),
        route_pattern: recommendation.route.clone(),
        match_mode: "exact".to_string(),
        route_type: route_type.to_string(),
        sensitivity: sensitivity.to_string(),
        auth_required: auth_required.to_string(),
        normal_traffic_pattern: normal_traffic_pattern.to_string(),
        recommended_actions,
        avoid_actions,
        evidence_json: evidence_json.to_string(),
        confidence: confidence.clamp(0, 100),
        source: if relearn_after_rejected {
            "local_ai_relearned".to_string()
        } else {
            "local_ai_observed".to_string()
        },
        status: "candidate".to_string(),
        rationale: format!(
            "local AI inferred route profile from {} defense depth with {} total events and {} hard events{}",
            recommendation.defense_depth,
            recommendation.total_events,
            recommendation.hard_events,
            if relearn_after_rejected {
                "; regenerated after previous rejection"
            } else {
                ""
            }
        ),
        last_observed_at: Some(now),
        reviewed_at: None,
    }
}

pub(super) fn ai_defense_identity_key(site_id: &str, route: &str) -> String {
    format!("{}|{}", site_id, route)
}

pub(super) fn split_ai_defense_identity_key(value: &str) -> Option<(String, String)> {
    let (site_id, route) = value.split_once('|')?;
    Some((site_id.to_string(), route.to_string()))
}

pub(super) fn ai_runtime_route_path(uri: &str) -> String {
    uri.split('?').next().unwrap_or(uri).to_string()
}

pub(super) fn metadata_true(request: &UnifiedHttpRequest, key: &str) -> bool {
    request
        .get_metadata(key)
        .is_some_and(|value| value == "true" || value == "1")
}

pub(super) fn classify_false_positive_risk(
    total_responses: u64,
    suspected_false_positive_events: u64,
    challenge_verified: u64,
    interactive_sessions: u64,
    blocked_responses: u64,
) -> &'static str {
    if total_responses == 0 {
        return "unknown";
    }
    if suspected_false_positive_events >= 3
        || (blocked_responses > 0
            && challenge_verified
                .saturating_add(interactive_sessions)
                .saturating_mul(2)
                >= total_responses)
    {
        "high"
    } else if suspected_false_positive_events > 0
        || challenge_verified
            .saturating_add(interactive_sessions)
            .saturating_mul(3)
            >= total_responses
    {
        "medium"
    } else {
        "low"
    }
}

pub(super) fn classify_route_effectiveness(
    bucket: &super::super::AiRouteResultBucket,
) -> &'static str {
    if bucket.total_responses < 5 {
        return "warming";
    }
    if bucket.suspected_false_positive_events >= 3 || bucket.upstream_errors >= 5 {
        return "harmful";
    }
    if bucket.policy_matched_responses >= 3
        && bucket.upstream_errors.saturating_mul(3) < bucket.total_responses
        && bucket.suspected_false_positive_events == 0
    {
        return "effective";
    }
    "neutral"
}

pub(super) fn compact_identity_value(value: &str) -> String {
    value.chars().take(96).collect()
}

pub(super) fn compact_user_agent(value: &str) -> String {
    let normalized = value.split_whitespace().collect::<Vec<_>>().join(" ");
    if normalized.len() <= 96 {
        normalized
    } else {
        normalized.chars().take(96).collect()
    }
}

pub(super) fn ai_defense_policy_signal(policy: &AiTempPolicyEntry) -> AiDefensePolicySignal {
    AiDefensePolicySignal {
        policy_key: policy.policy_key.clone(),
        scope_type: policy.scope_type.clone(),
        scope_value: policy.scope_value.clone(),
        action: policy.action.clone(),
        hit_count: policy.hit_count,
        expires_at: policy.expires_at,
    }
}

pub(super) fn ai_defense_policy_effect_signal(
    policy: &AiTempPolicyEntry,
) -> Option<AiDefensePolicyEffectSignal> {
    let effect =
        serde_json::from_str::<AiTempPolicyEffectStats>(&policy.effect_json).unwrap_or_default();
    if effect.post_policy_observations == 0 && effect.total_hits == 0 {
        return None;
    }
    Some(AiDefensePolicyEffectSignal {
        policy_key: policy.policy_key.clone(),
        scope_type: policy.scope_type.clone(),
        scope_value: policy.scope_value.clone(),
        action: policy.action.clone(),
        hit_count: policy.hit_count,
        outcome_status: effect
            .outcome_status
            .unwrap_or_else(|| "warming".to_string()),
        outcome_score: effect.outcome_score,
        observations: effect.post_policy_observations,
        upstream_errors: effect.post_policy_upstream_errors,
        suspected_false_positive_events: effect.suspected_false_positive_events,
        challenge_verified: effect.post_policy_challenge_verified,
        pressure_after_observations: effect.pressure_after_observations,
    })
}

pub(super) fn ai_defense_route_profile_signal(
    profile: AiRouteProfileEntry,
) -> AiDefenseRouteProfileSignal {
    let raw_confidence = profile.confidence;
    let (confidence, staleness_secs) = route_profile_effective_confidence(&profile);
    AiDefenseRouteProfileSignal {
        site_id: profile.site_id,
        route_pattern: profile.route_pattern,
        match_mode: profile.match_mode,
        route_type: profile.route_type,
        sensitivity: profile.sensitivity,
        auth_required: profile.auth_required,
        normal_traffic_pattern: profile.normal_traffic_pattern,
        recommended_actions: serde_json::from_str(&profile.recommended_actions_json)
            .unwrap_or_default(),
        avoid_actions: serde_json::from_str(&profile.avoid_actions_json).unwrap_or_default(),
        evidence: serde_json::from_str(&profile.evidence_json)
            .unwrap_or_else(|_| serde_json::json!({})),
        raw_confidence,
        staleness_secs,
        confidence,
        source: profile.source,
        status: profile.status,
        rationale: profile.rationale,
    }
}

fn route_profile_effective_confidence(profile: &AiRouteProfileEntry) -> (i64, Option<u64>) {
    let Some(last_observed_at) = profile.last_observed_at else {
        return (profile.confidence, None);
    };
    let staleness_secs = unix_timestamp().saturating_sub(last_observed_at).max(0) as u64;
    let grace_days = if profile.reviewed_at.is_some() {
        30
    } else {
        14
    };
    let stale_days = staleness_secs / 86_400;
    let penalty = stale_days
        .saturating_sub(grace_days)
        .saturating_mul(2)
        .min(30) as i64;
    (
        profile.confidence.saturating_sub(penalty).clamp(0, 100),
        Some(staleness_secs),
    )
}

pub(super) fn ai_defense_decision_allowed(
    decision: &AiDefenseDecision,
    min_confidence: u32,
) -> bool {
    decision.auto_apply
        && decision.confidence as u32 >= min_confidence
        && matches!(
            decision.action.as_str(),
            "tighten_route_cc"
                | "tighten_host_cc"
                | "increase_delay"
                | "increase_challenge"
                | "raise_identity_risk"
                | "add_behavior_watch"
        )
        && decision.layer == "l7"
        && decision.scope_type == "route"
        && ai_defense_route_allowed(&decision.scope_value)
}

pub(super) fn ai_defense_route_allowed(route: &str) -> bool {
    route.starts_with('/')
        && route != "/"
        && route.len() <= 256
        && !route.contains("..")
        && route != "/favicon.ico"
        && route != "/robots.txt"
        && route != "/sitemap.xml"
        && !route.starts_with("/.well-known/")
        && !route.starts_with("/assets/")
        && !route.starts_with("/static/")
}
