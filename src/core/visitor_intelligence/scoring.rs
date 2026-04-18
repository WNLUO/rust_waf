use super::types::{VisitorDecisionSignal, VisitorIntelligenceBucket, VisitorProfileSignal};
use super::utils::{stable_hash, top_routes};

pub(super) fn profile_signal_from_bucket(
    bucket: &VisitorIntelligenceBucket,
) -> VisitorProfileSignal {
    let mut flags = bucket.flags.iter().cloned().collect::<Vec<_>>();
    flags.sort();
    let route_summary = top_routes(&bucket.route_counts, 8);
    let route_diversity = bucket.route_counts.len() as u64;
    let mut human = 20u8;
    let mut automation = 0u8;
    let mut probe = 0u8;
    let mut abuse = 0u8;

    if bucket.fingerprint_seen {
        human = human.saturating_add(30);
    }
    if bucket.challenge_verified_count > 0 {
        human = human.saturating_add(25);
    }
    if bucket.challenge_js_report_count > 0 {
        human = human.saturating_add(10);
    }
    if bucket.static_count >= bucket.document_count.max(1) {
        human = human.saturating_add(10);
    }
    if bucket.same_site_referer_count > 0 {
        human = human.saturating_add(10);
    }
    if bucket.admin_count > 0 && (bucket.fingerprint_seen || bucket.same_site_referer_count > 0) {
        human = human.saturating_add(10);
    }
    if bucket.document_count >= 8 && bucket.static_count == 0 {
        automation = automation.saturating_add(35);
    }
    if bucket.document_count >= 6 && route_diversity <= 2 {
        automation = automation.saturating_add(25);
    }
    if bucket.no_referer_document_count >= 5 {
        automation = automation.saturating_add(15);
    }
    if bucket.admin_count >= 3 && !bucket.fingerprint_seen {
        probe = probe.saturating_add(40);
    }
    if bucket.auth_rejected_count >= 3 && bucket.auth_success_count == 0 {
        probe = probe.saturating_add(25);
    }
    if bucket.status_codes.get("404").copied().unwrap_or(0) >= 3
        || bucket.status_codes.get("403").copied().unwrap_or(0) >= 3
    {
        probe = probe.saturating_add(20);
    }
    if bucket.blocked_response_count > 0 {
        abuse = abuse.saturating_add(25);
    }
    if bucket.challenge_count >= 2 && bucket.challenge_verified_count == 0 {
        abuse = abuse.saturating_add(25);
    }
    if bucket.api_count >= 10 && !bucket.fingerprint_seen {
        abuse = abuse.saturating_add(20);
    }
    if human >= 70 {
        automation = automation.saturating_sub(20);
        probe = probe.saturating_sub(15);
        abuse = abuse.saturating_sub(10);
    }

    let false_positive_risk = if human >= 75 && (automation >= 35 || abuse >= 25) {
        "high"
    } else if human >= 55 {
        "medium"
    } else {
        "low"
    }
    .to_string();
    let state = if bucket.fingerprint_seen && bucket.admin_count > 0 {
        "admin_session"
    } else if human >= 75 {
        "trusted_session"
    } else if probe >= 45 {
        "suspected_probe"
    } else if automation >= 50 {
        "suspected_crawler"
    } else if abuse >= 45 {
        "suspected_abuse"
    } else if bucket.challenge_count > 0 {
        "challenged"
    } else {
        "observing"
    }
    .to_string();
    let tracking_priority = if matches!(state.as_str(), "suspected_probe" | "suspected_abuse") {
        "high"
    } else if automation >= 35 || false_positive_risk != "low" {
        "medium"
    } else {
        "low"
    }
    .to_string();
    let ai_rationale = format!(
        "state={} human={} automation={} probe={} abuse={} docs={} static={} api={} admin={} verified={} fp={} challenge_js={} upstream_success={} upstream_error={} auth_required={} auth_success={} auth_rejected={} business_types={:?} routes={}",
        state,
        human,
        automation,
        probe,
        abuse,
        bucket.document_count,
        bucket.static_count,
        bucket.api_count,
        bucket.admin_count,
        bucket.challenge_verified_count,
        bucket.fingerprint_seen,
        bucket.challenge_js_report_count,
        bucket.upstream_success_count,
        bucket.upstream_error_count,
        bucket.auth_required_route_count,
        bucket.auth_success_count,
        bucket.auth_rejected_count,
        bucket.business_route_types,
        bucket.route_counts.len()
    );
    VisitorProfileSignal {
        identity_key: bucket.identity_key.clone(),
        identity_source: bucket.identity_source.clone(),
        site_id: bucket.site_id.clone(),
        client_ip: bucket.client_ip.clone(),
        user_agent: bucket.user_agent.clone(),
        state,
        first_seen_at: bucket.first_seen_at,
        last_seen_at: bucket.last_seen_at,
        request_count: bucket.request_count,
        document_count: bucket.document_count,
        api_count: bucket.api_count,
        static_count: bucket.static_count,
        admin_count: bucket.admin_count,
        challenge_count: bucket.challenge_count,
        challenge_verified_count: bucket.challenge_verified_count,
        challenge_page_report_count: bucket.challenge_page_report_count,
        challenge_js_report_count: bucket.challenge_js_report_count,
        fingerprint_seen: bucket.fingerprint_seen,
        upstream_success_count: bucket.upstream_success_count,
        upstream_redirect_count: bucket.upstream_redirect_count,
        upstream_client_error_count: bucket.upstream_client_error_count,
        upstream_error_count: bucket.upstream_error_count,
        auth_required_route_count: bucket.auth_required_route_count,
        auth_success_count: bucket.auth_success_count,
        auth_rejected_count: bucket.auth_rejected_count,
        human_confidence: human.min(100),
        automation_risk: automation.min(100),
        probe_risk: probe.min(100),
        abuse_risk: abuse.min(100),
        false_positive_risk,
        tracking_priority,
        route_summary,
        business_route_types: bucket.business_route_types.clone(),
        status_codes: bucket.status_codes.clone(),
        flags,
        ai_rationale,
    }
}

pub(super) fn visitor_decision_from_profile(
    profile: &VisitorProfileSignal,
) -> Option<VisitorDecisionSignal> {
    if profile.request_count < 6 && profile.admin_count < 2 {
        return None;
    }
    let (action, confidence, ttl_secs, rationale) = if profile.false_positive_risk == "high" {
        (
            "reduce_friction",
            86,
            900,
            "visitor has strong human signals while still receiving friction",
        )
    } else if matches!(
        profile.state.as_str(),
        "suspected_probe" | "suspected_abuse"
    ) {
        (
            "increase_challenge",
            88,
            900,
            "visitor shows sensitive-route probing or abuse signals",
        )
    } else if profile.state == "suspected_crawler" {
        (
            "watch_visitor",
            84,
            900,
            "visitor looks automated but not severe enough for blocking",
        )
    } else if profile.state == "trusted_session" || profile.state == "admin_session" {
        (
            "mark_trusted_temporarily",
            82,
            900,
            "visitor has browser verification and normal session signals",
        )
    } else {
        return None;
    };
    Some(VisitorDecisionSignal {
        decision_key: format!("visitor:{}:{}", action, stable_hash(&profile.identity_key)),
        identity_key: profile.identity_key.clone(),
        site_id: profile.site_id.clone(),
        action: action.to_string(),
        confidence,
        ttl_secs,
        rationale: format!("{}; {}", rationale, profile.ai_rationale),
        applied: false,
        effect_status: "pending".to_string(),
    })
}
