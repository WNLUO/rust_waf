use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EarlyDefenseAction {
    Allow,
    LightweightL7,
    Challenge,
    Drop,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EarlyDefenseDecision {
    pub(crate) action: EarlyDefenseAction,
    pub(crate) reason: &'static str,
    pub(crate) route_threshold_scale_percent: Option<u32>,
    pub(crate) host_threshold_scale_percent: Option<u32>,
    pub(crate) force_close: bool,
}

impl EarlyDefenseDecision {
    fn allow() -> Self {
        Self {
            action: EarlyDefenseAction::Allow,
            reason: "allow",
            route_threshold_scale_percent: None,
            host_threshold_scale_percent: None,
            force_close: false,
        }
    }

    fn lightweight(reason: &'static str, route_scale: u32, host_scale: u32) -> Self {
        Self {
            action: EarlyDefenseAction::LightweightL7,
            reason,
            route_threshold_scale_percent: Some(route_scale),
            host_threshold_scale_percent: Some(host_scale),
            force_close: true,
        }
    }

    fn challenge(reason: &'static str, route_scale: u32, host_scale: u32) -> Self {
        Self {
            action: EarlyDefenseAction::Challenge,
            reason,
            route_threshold_scale_percent: Some(route_scale),
            host_threshold_scale_percent: Some(host_scale),
            force_close: true,
        }
    }

    fn drop(reason: &'static str) -> Self {
        Self {
            action: EarlyDefenseAction::Drop,
            reason,
            route_threshold_scale_percent: Some(35),
            host_threshold_scale_percent: Some(50),
            force_close: true,
        }
    }
}

pub(crate) fn evaluate_early_defense(request: &mut UnifiedHttpRequest) -> Option<InspectionResult> {
    let decision = early_defense_decision(request);
    apply_early_defense_decision(request, &decision);
    if matches!(decision.action, EarlyDefenseAction::Drop) {
        return Some(InspectionResult::drop(
            InspectionLayer::L7,
            format!("early defense dropped request: {}", decision.reason),
        ));
    }
    None
}

pub(crate) fn early_defense_decision(request: &UnifiedHttpRequest) -> EarlyDefenseDecision {
    let identity_state = metadata(request, "network.identity_state");
    let runtime_depth = metadata(request, "runtime.defense.depth");
    let runtime_level = metadata(request, "runtime.pressure.level");
    let l4_risk = metadata(request, "l4.bucket_risk");
    let l4_overload = metadata(request, "l4.overload_level");
    let storage_queue_percent = metadata_u64(request, "runtime.pressure.storage_queue_percent");
    let cpu_score = metadata_u8(request, "runtime.pressure.cpu_score");
    let adaptive_pressure = metadata(request, "runtime.adaptive.system_pressure");
    let identity_pressure = metadata_f64(request, "runtime.adaptive.identity_pressure_percent");
    let l7_friction_pressure =
        metadata_f64(request, "runtime.adaptive.l7_friction_pressure_percent");
    let slow_attack_pressure =
        metadata_f64(request, "runtime.adaptive.slow_attack_pressure_percent");
    let identity_windows = metadata_u8(request, "runtime.auto_tuning.identity_windows");
    let slow_attack_windows = metadata_u8(request, "runtime.auto_tuning.slow_attack_windows");
    let budget_windows = metadata_u8(request, "runtime.auto_tuning.budget_windows");
    let latency_windows = metadata_u8(request, "runtime.auto_tuning.latency_windows");
    let prefer_drop = metadata_bool(request, "runtime.prefer_drop");
    let request_budget_softened = metadata_bool(request, "l4.request_budget_softened");
    let site_action = metadata(request, "runtime.site.action");
    let site_proxy_mode = metadata(request, "runtime.site.proxy_mode");
    let site_priority = metadata(request, "runtime.site.priority");
    let site_over_rps_budget = metadata_bool(request, "runtime.site.over_rps_budget");

    if site_proxy_mode == Some("shed") && (prefer_drop || matches!(runtime_depth, Some("survival")))
    {
        return EarlyDefenseDecision::drop("site_shed_under_runtime_pressure");
    }

    if site_action == Some("block") && site_over_rps_budget {
        return EarlyDefenseDecision::drop("site_block_first_budget_exceeded");
    }

    if site_action == Some("challenge") && site_over_rps_budget {
        let (route_scale, host_scale) = if site_priority == Some("critical") {
            (70, 80)
        } else {
            (55, 70)
        };
        return EarlyDefenseDecision::lightweight(
            "site_challenge_first_budget_exceeded",
            route_scale,
            host_scale,
        );
    }

    if identity_state == Some("spoofed_forward_header")
        && (matches!(runtime_level, Some("high" | "attack"))
            || should_hard_drop_under_pressure(
                prefer_drop,
                runtime_depth,
                runtime_level,
                l4_overload,
                storage_queue_percent,
                cpu_score,
                adaptive_pressure,
                identity_pressure,
                l7_friction_pressure,
                slow_attack_pressure,
                identity_windows,
                slow_attack_windows,
                budget_windows,
                latency_windows,
            ))
    {
        return EarlyDefenseDecision::drop("spoofed_forward_header_under_pressure");
    }

    if identity_state == Some("trusted_cdn_unresolved") && matches!(runtime_depth, Some("survival"))
    {
        return EarlyDefenseDecision::drop("trusted_cdn_unresolved_survival");
    }

    if metadata_bool(request, "l7.cc.survival_verified_normal")
        || (matches!(runtime_depth, Some("survival"))
            && is_low_risk_stable_identity_candidate(request))
    {
        return EarlyDefenseDecision::allow();
    }

    if request_budget_softened && matches!(runtime_depth, Some("survival")) {
        return EarlyDefenseDecision::drop("l4_request_budget_softened_survival");
    }

    if matches!(l4_risk, Some("high")) {
        if should_hard_drop_under_pressure(
            prefer_drop,
            runtime_depth,
            runtime_level,
            l4_overload,
            storage_queue_percent,
            cpu_score,
            adaptive_pressure,
            identity_pressure,
            l7_friction_pressure,
            slow_attack_pressure,
            identity_windows,
            slow_attack_windows,
            budget_windows,
            latency_windows,
        ) {
            return EarlyDefenseDecision::drop("l4_high_risk_runtime_pressure");
        }
        if should_force_challenge_under_pressure(
            runtime_depth,
            runtime_level,
            l4_overload,
            storage_queue_percent,
            cpu_score,
            adaptive_pressure,
            identity_pressure,
            l7_friction_pressure,
            slow_attack_pressure,
            identity_windows,
            slow_attack_windows,
            budget_windows,
            latency_windows,
        ) {
            return EarlyDefenseDecision::challenge("l4_high_risk_force_challenge", 35, 50);
        }
        return EarlyDefenseDecision::lightweight("l4_high_risk_tighten_l7", 45, 60);
    }

    if matches!(l4_risk, Some("suspicious")) {
        if matches!(runtime_depth, Some("survival"))
            && should_hard_drop_under_pressure(
                prefer_drop,
                runtime_depth,
                runtime_level,
                l4_overload,
                storage_queue_percent,
                cpu_score,
                adaptive_pressure,
                identity_pressure,
                l7_friction_pressure,
                slow_attack_pressure,
                identity_windows,
                slow_attack_windows,
                budget_windows,
                latency_windows,
            )
        {
            return EarlyDefenseDecision::drop("l4_suspicious_survival_pressure");
        }
        if should_force_challenge_under_pressure(
            runtime_depth,
            runtime_level,
            l4_overload,
            storage_queue_percent,
            cpu_score,
            adaptive_pressure,
            identity_pressure,
            l7_friction_pressure,
            slow_attack_pressure,
            identity_windows,
            slow_attack_windows,
            budget_windows,
            latency_windows,
        ) {
            return EarlyDefenseDecision::challenge("l4_suspicious_force_challenge", 55, 70);
        }
        return EarlyDefenseDecision::lightweight("l4_suspicious_tighten_l7", 70, 80);
    }

    if matches!(runtime_depth, Some("survival"))
        && matches!(identity_state, Some("trusted_cdn_forwarded"))
        && cpu_score >= 3
    {
        return EarlyDefenseDecision::lightweight("trusted_cdn_survival_tighten_l7", 60, 75);
    }

    EarlyDefenseDecision::allow()
}

fn apply_early_defense_decision(request: &mut UnifiedHttpRequest, decision: &EarlyDefenseDecision) {
    if matches!(decision.action, EarlyDefenseAction::Allow) {
        return;
    }

    request.add_metadata(
        "early_defense.action".to_string(),
        match decision.action {
            EarlyDefenseAction::Allow => "allow",
            EarlyDefenseAction::LightweightL7 => "lightweight_l7",
            EarlyDefenseAction::Challenge => "challenge",
            EarlyDefenseAction::Drop => "drop",
        }
        .to_string(),
    );
    request.add_metadata(
        "early_defense.reason".to_string(),
        decision.reason.to_string(),
    );

    if decision.force_close {
        request.add_metadata("l4.force_close".to_string(), "true".to_string());
        request.add_metadata("proxy_connection_mode".to_string(), "close".to_string());
    }
    if matches!(decision.action, EarlyDefenseAction::Drop) {
        request.add_metadata("l7.enforcement".to_string(), "drop".to_string());
        request.add_metadata("l7.drop_reason".to_string(), "early_defense".to_string());
    }
    if matches!(decision.action, EarlyDefenseAction::Challenge) {
        request.add_metadata("ai.cc.force_challenge".to_string(), "true".to_string());
        request.add_metadata("l7.enforcement".to_string(), "respond".to_string());
    }
    if let Some(value) = decision.route_threshold_scale_percent {
        set_min_percent_metadata(request, "ai.cc.route_threshold_scale_percent", value);
    }
    if let Some(value) = decision.host_threshold_scale_percent {
        set_min_percent_metadata(request, "ai.cc.host_threshold_scale_percent", value);
    }
}

fn set_min_percent_metadata(request: &mut UnifiedHttpRequest, key: &str, value: u32) {
    let next = request
        .get_metadata(key)
        .and_then(|current| current.parse::<u32>().ok())
        .map(|current| current.min(value))
        .unwrap_or(value)
        .clamp(10, 100);
    request.add_metadata(key.to_string(), next.to_string());
}

fn metadata<'a>(request: &'a UnifiedHttpRequest, key: &str) -> Option<&'a str> {
    request.get_metadata(key).map(String::as_str)
}

fn metadata_bool(request: &UnifiedHttpRequest, key: &str) -> bool {
    metadata(request, key)
        .map(|value| value == "true")
        .unwrap_or(false)
}

fn metadata_u8(request: &UnifiedHttpRequest, key: &str) -> u8 {
    metadata(request, key)
        .and_then(|value| value.parse::<u8>().ok())
        .unwrap_or(0)
}

fn metadata_u64(request: &UnifiedHttpRequest, key: &str) -> u64 {
    metadata(request, key)
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0)
}

fn metadata_f64(request: &UnifiedHttpRequest, key: &str) -> f64 {
    metadata(request, key)
        .and_then(|value| value.parse::<f64>().ok())
        .unwrap_or(0.0)
}

fn should_hard_drop_under_pressure(
    prefer_drop: bool,
    runtime_depth: Option<&str>,
    runtime_level: Option<&str>,
    l4_overload: Option<&str>,
    storage_queue_percent: u64,
    cpu_score: u8,
    adaptive_pressure: Option<&str>,
    identity_pressure: f64,
    l7_friction_pressure: f64,
    slow_attack_pressure: f64,
    identity_windows: u8,
    slow_attack_windows: u8,
    budget_windows: u8,
    latency_windows: u8,
) -> bool {
    if prefer_drop {
        return true;
    }

    let survival = matches!(runtime_depth, Some("survival"));
    let runtime_high = matches!(runtime_level, Some("high" | "attack"));
    let runtime_attack = matches!(runtime_level, Some("attack"));
    let adaptive_high = matches!(adaptive_pressure, Some("high" | "attack"));
    let adaptive_attack = matches!(adaptive_pressure, Some("attack"));
    let overload_high = matches!(l4_overload, Some("high" | "critical"));
    let overload_critical = matches!(l4_overload, Some("critical"));
    let queue_hot = storage_queue_percent >= 90;
    let queue_warm = storage_queue_percent >= 75;
    let identity_hot = identity_pressure >= 5.0;
    let friction_hot = l7_friction_pressure >= 25.0;
    let slow_attack_hot = slow_attack_pressure >= 2.0;
    let defense_heat = [identity_hot, friction_hot, slow_attack_hot]
        .into_iter()
        .filter(|hot| *hot)
        .count();
    let persistent_heat = [
        identity_windows >= 2,
        slow_attack_windows >= 2,
        budget_windows >= 2,
        latency_windows >= 2,
    ]
    .into_iter()
    .filter(|hot| *hot)
    .count();

    if overload_critical && (survival || runtime_high || queue_warm || cpu_score >= 2) {
        return true;
    }
    if survival
        && (runtime_attack || adaptive_attack || queue_hot || defense_heat >= 2 || persistent_heat >= 2)
    {
        return true;
    }
    if cpu_score >= 3 && (queue_warm || runtime_high || adaptive_high || overload_high) {
        return true;
    }
    if queue_hot && (runtime_high || adaptive_high || overload_high || defense_heat >= 1) {
        return true;
    }
    if defense_heat >= 2 && (runtime_high || adaptive_high || overload_high || persistent_heat >= 1)
    {
        return true;
    }
    if persistent_heat >= 2 && (runtime_high || adaptive_high || queue_warm || overload_high) {
        return true;
    }

    false
}

fn should_force_challenge_under_pressure(
    runtime_depth: Option<&str>,
    runtime_level: Option<&str>,
    l4_overload: Option<&str>,
    storage_queue_percent: u64,
    cpu_score: u8,
    adaptive_pressure: Option<&str>,
    identity_pressure: f64,
    l7_friction_pressure: f64,
    slow_attack_pressure: f64,
    identity_windows: u8,
    slow_attack_windows: u8,
    budget_windows: u8,
    latency_windows: u8,
) -> bool {
    let survival = matches!(runtime_depth, Some("survival"));
    let runtime_high = matches!(runtime_level, Some("high" | "attack"));
    let adaptive_high = matches!(adaptive_pressure, Some("high" | "attack"));
    let overload_high = matches!(l4_overload, Some("high" | "critical"));
    let queue_warm = storage_queue_percent >= 75;
    let defense_heat = [
        identity_pressure >= 5.0,
        l7_friction_pressure >= 25.0,
        slow_attack_pressure >= 2.0,
    ]
    .into_iter()
    .filter(|hot| *hot)
    .count();
    let persistent_heat = [
        identity_windows >= 2,
        slow_attack_windows >= 2,
        budget_windows >= 2,
        latency_windows >= 2,
    ]
    .into_iter()
    .filter(|hot| *hot)
    .count();

    if survival && (defense_heat >= 1 || persistent_heat >= 1 || queue_warm) {
        return true;
    }
    if overload_high && (runtime_high || adaptive_high || persistent_heat >= 1) {
        return true;
    }
    if cpu_score >= 2 && (adaptive_high || queue_warm || persistent_heat >= 1) {
        return true;
    }
    if defense_heat >= 1 && (runtime_high || adaptive_high || queue_warm || persistent_heat >= 1) {
        return true;
    }
    if persistent_heat >= 2 {
        return true;
    }

    false
}

fn is_low_risk_stable_identity_candidate(request: &UnifiedHttpRequest) -> bool {
    let method = request.method.to_ascii_uppercase();
    if method != "GET" && method != "HEAD" {
        return false;
    }
    let path = request.uri.split('?').next().unwrap_or("/");
    if path.starts_with("/api/") {
        return false;
    }
    let Some(identity) = stable_browser_identity(request) else {
        return false;
    };
    if identity.len() < 6 || identity.len() > 128 {
        return false;
    }
    let sec_fetch_site = request
        .get_header("sec-fetch-site")
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_default();
    if !matches!(sec_fetch_site.as_str(), "same-origin" | "same-site") {
        return false;
    }
    if looks_like_static_asset(path)
        || path == "/"
        || path.ends_with(".html")
        || path.ends_with(".htm")
    {
        return true;
    }
    if request
        .get_header("sec-fetch-dest")
        .map(|value| value.eq_ignore_ascii_case("document"))
        .unwrap_or(false)
    {
        return true;
    }
    request
        .get_header("accept")
        .map(|value| {
            let accept = value.to_ascii_lowercase();
            accept.contains("text/html") || accept.contains("application/xhtml+xml")
        })
        .unwrap_or(false)
}

fn stable_browser_identity(request: &UnifiedHttpRequest) -> Option<&str> {
    let cookie_fp = cookie_value(request, "rwaf_fp").filter(|value| !value.trim().is_empty());
    let header_fp = request
        .get_header("x-browser-fingerprint-id")
        .map(String::as_str)
        .filter(|value| !value.trim().is_empty());

    match (cookie_fp, header_fp) {
        (Some(cookie), Some(header)) if cookie == header => Some(cookie),
        (Some(cookie), None) => Some(cookie),
        (None, Some(header)) => Some(header),
        _ => None,
    }
}

fn cookie_value<'a>(request: &'a UnifiedHttpRequest, name: &str) -> Option<&'a str> {
    request.get_header("cookie").and_then(|header| {
        header.split(';').find_map(|part| {
            let trimmed = part.trim();
            let (key, value) = trimmed.split_once('=')?;
            if key.trim() == name {
                Some(value.trim())
            } else {
                None
            }
        })
    })
}

fn looks_like_static_asset(path: &str) -> bool {
    let path = path.to_ascii_lowercase();
    [
        ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".woff", ".woff2",
        ".ttf", ".map",
    ]
    .iter()
    .any(|suffix| path.ends_with(suffix))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> UnifiedHttpRequest {
        UnifiedHttpRequest::new(HttpVersion::Http1_1, "GET".to_string(), "/api".to_string())
    }

    #[test]
    fn high_l4_risk_tightens_l7_under_medium_cpu_pressure() {
        let mut request = request();
        request.add_metadata("l4.bucket_risk".to_string(), "high".to_string());
        request.add_metadata("runtime.pressure.cpu_score".to_string(), "2".to_string());

        assert!(evaluate_early_defense(&mut request).is_none());
        assert_eq!(
            request.get_metadata("early_defense.action").unwrap(),
            "lightweight_l7"
        );
        assert_eq!(
            request
                .get_metadata("ai.cc.route_threshold_scale_percent")
                .unwrap(),
            "45"
        );
    }

    #[test]
    fn high_l4_risk_extreme_cpu_alone_only_tightens_l7() {
        let mut request = request();
        request.add_metadata("l4.bucket_risk".to_string(), "high".to_string());
        request.add_metadata("runtime.pressure.cpu_score".to_string(), "3".to_string());

        assert!(evaluate_early_defense(&mut request).is_none());
        assert_eq!(
            request.get_metadata("early_defense.action").unwrap(),
            "lightweight_l7"
        );
        assert_eq!(
            request
                .get_metadata("ai.cc.route_threshold_scale_percent")
                .unwrap(),
            "45"
        );
    }

    #[test]
    fn high_l4_risk_persistent_identity_pressure_forces_challenge() {
        let mut request = request();
        request.add_metadata("l4.bucket_risk".to_string(), "high".to_string());
        request.add_metadata("runtime.auto_tuning.identity_windows".to_string(), "2".to_string());
        request.add_metadata(
            "runtime.adaptive.identity_pressure_percent".to_string(),
            "6.20".to_string(),
        );

        assert!(evaluate_early_defense(&mut request).is_none());
        assert_eq!(
            request.get_metadata("early_defense.action").unwrap(),
            "challenge"
        );
        assert_eq!(
            request.get_metadata("ai.cc.force_challenge").unwrap(),
            "true"
        );
        assert_eq!(
            request
                .get_metadata("ai.cc.route_threshold_scale_percent")
                .unwrap(),
            "35"
        );
    }

    #[test]
    fn high_l4_risk_drops_under_extreme_cpu_with_queue_pressure() {
        let mut request = request();
        request.add_metadata("l4.bucket_risk".to_string(), "high".to_string());
        request.add_metadata("runtime.pressure.cpu_score".to_string(), "3".to_string());
        request.add_metadata(
            "runtime.pressure.storage_queue_percent".to_string(),
            "80".to_string(),
        );

        let result = evaluate_early_defense(&mut request).expect("drop decision");

        assert!(result.blocked);
        assert_eq!(
            request.get_metadata("early_defense.action").unwrap(),
            "drop"
        );
        assert_eq!(request.get_metadata("l7.enforcement").unwrap(), "drop");
        assert_eq!(
            request
                .get_metadata("ai.cc.route_threshold_scale_percent")
                .unwrap(),
            "35"
        );
    }

    #[test]
    fn suspicious_l4_risk_tightens_l7_without_drop() {
        let mut request = request();
        request.add_metadata("l4.bucket_risk".to_string(), "suspicious".to_string());

        assert!(evaluate_early_defense(&mut request).is_none());
        assert_eq!(
            request.get_metadata("early_defense.action").unwrap(),
            "lightweight_l7"
        );
        assert_eq!(
            request
                .get_metadata("ai.cc.route_threshold_scale_percent")
                .unwrap(),
            "70"
        );
    }

    #[test]
    fn suspicious_l4_risk_survival_heat_forces_challenge_before_drop() {
        let mut request = request();
        request.add_metadata("l4.bucket_risk".to_string(), "suspicious".to_string());
        request.add_metadata("runtime.defense.depth".to_string(), "survival".to_string());
        request.add_metadata(
            "runtime.adaptive.identity_pressure_percent".to_string(),
            "6.20".to_string(),
        );

        assert!(evaluate_early_defense(&mut request).is_none());
        assert_eq!(
            request.get_metadata("early_defense.action").unwrap(),
            "challenge"
        );
        assert_eq!(
            request.get_metadata("ai.cc.force_challenge").unwrap(),
            "true"
        );
    }

    #[test]
    fn suspicious_l4_risk_in_survival_needs_compound_pressure_to_drop() {
        let mut relaxed = request();
        relaxed.add_metadata("l4.bucket_risk".to_string(), "suspicious".to_string());
        relaxed.add_metadata("runtime.defense.depth".to_string(), "survival".to_string());
        relaxed.add_metadata("runtime.pressure.cpu_score".to_string(), "3".to_string());

        assert!(evaluate_early_defense(&mut relaxed).is_none());
        assert_eq!(
            relaxed.get_metadata("early_defense.action").unwrap(),
            "lightweight_l7"
        );

        let mut pressured = request();
        pressured.add_metadata("l4.bucket_risk".to_string(), "suspicious".to_string());
        pressured.add_metadata("runtime.defense.depth".to_string(), "survival".to_string());
        pressured.add_metadata("runtime.pressure.cpu_score".to_string(), "3".to_string());
        pressured.add_metadata("l4.overload_level".to_string(), "high".to_string());

        let result = evaluate_early_defense(&mut pressured).expect("drop decision");
        assert!(result.blocked);
        assert_eq!(
            pressured.get_metadata("early_defense.reason").unwrap(),
            "l4_suspicious_survival_pressure"
        );
    }

    #[test]
    fn high_l4_risk_drops_under_compound_adaptive_pressure() {
        let mut request = request();
        request.add_metadata("l4.bucket_risk".to_string(), "high".to_string());
        request.add_metadata("runtime.adaptive.system_pressure".to_string(), "high".to_string());
        request.add_metadata(
            "runtime.adaptive.identity_pressure_percent".to_string(),
            "6.20".to_string(),
        );
        request.add_metadata(
            "runtime.adaptive.l7_friction_pressure_percent".to_string(),
            "28.00".to_string(),
        );

        let result = evaluate_early_defense(&mut request).expect("drop decision");
        assert!(result.blocked);
        assert_eq!(
            request.get_metadata("early_defense.reason").unwrap(),
            "l4_high_risk_runtime_pressure"
        );
    }

    #[test]
    fn high_l4_risk_drops_under_persistent_multi_window_pressure() {
        let mut request = request();
        request.add_metadata("l4.bucket_risk".to_string(), "high".to_string());
        request.add_metadata("runtime.pressure.level".to_string(), "high".to_string());
        request.add_metadata("runtime.auto_tuning.identity_windows".to_string(), "2".to_string());
        request.add_metadata("runtime.auto_tuning.budget_windows".to_string(), "2".to_string());

        let result = evaluate_early_defense(&mut request).expect("drop decision");
        assert!(result.blocked);
        assert_eq!(
            request.get_metadata("early_defense.reason").unwrap(),
            "l4_high_risk_runtime_pressure"
        );
    }

    #[test]
    fn trusted_cdn_unresolved_drops_in_survival() {
        let mut request = request();
        request.add_metadata(
            "network.identity_state".to_string(),
            "trusted_cdn_unresolved".to_string(),
        );
        request.add_metadata("runtime.defense.depth".to_string(), "survival".to_string());

        let result = evaluate_early_defense(&mut request).expect("drop decision");

        assert!(result.blocked);
        assert_eq!(
            request.get_metadata("early_defense.reason").unwrap(),
            "trusted_cdn_unresolved_survival"
        );
    }

    #[test]
    fn survival_verified_normal_survives_broad_l4_pressure() {
        let mut request = request();
        request.add_metadata(
            "network.identity_state".to_string(),
            "trusted_cdn_forwarded".to_string(),
        );
        request.add_metadata("runtime.defense.depth".to_string(), "survival".to_string());
        request.add_metadata("l4.bucket_risk".to_string(), "high".to_string());
        request.add_metadata("l4.overload_level".to_string(), "critical".to_string());
        request.add_metadata("l4.request_budget_softened".to_string(), "true".to_string());
        request.add_metadata(
            "l7.cc.survival_verified_normal".to_string(),
            "true".to_string(),
        );

        assert!(evaluate_early_defense(&mut request).is_none());
        assert!(request.get_metadata("early_defense.action").is_none());
        assert!(request.get_metadata("l7.enforcement").is_none());
    }

    #[test]
    fn stable_document_identity_survives_before_l7_verified_marker() {
        let mut request = request();
        request.uri = "/health?n=1".to_string();
        request.add_metadata(
            "network.identity_state".to_string(),
            "trusted_cdn_forwarded".to_string(),
        );
        request.add_metadata("runtime.defense.depth".to_string(), "survival".to_string());
        request.add_metadata("l4.bucket_risk".to_string(), "high".to_string());
        request.add_metadata("l4.overload_level".to_string(), "critical".to_string());
        request.add_header("cookie".to_string(), "rwaf_fp=stable-normal".to_string());
        request.add_header(
            "x-browser-fingerprint-id".to_string(),
            "stable-normal".to_string(),
        );
        request.add_header("sec-fetch-site".to_string(), "same-origin".to_string());
        request.add_header("sec-fetch-dest".to_string(), "document".to_string());

        assert!(evaluate_early_defense(&mut request).is_none());
        assert!(request.get_metadata("early_defense.action").is_none());
    }

    #[test]
    fn api_identity_candidate_still_drops_under_l4_pressure() {
        let mut request = request();
        request.uri = "/api/search".to_string();
        request.add_metadata(
            "network.identity_state".to_string(),
            "trusted_cdn_forwarded".to_string(),
        );
        request.add_metadata("runtime.defense.depth".to_string(), "survival".to_string());
        request.add_metadata("l4.bucket_risk".to_string(), "high".to_string());
        request.add_metadata("l4.overload_level".to_string(), "critical".to_string());
        request.add_header("cookie".to_string(), "rwaf_fp=stable-normal".to_string());
        request.add_header(
            "x-browser-fingerprint-id".to_string(),
            "stable-normal".to_string(),
        );
        request.add_header("sec-fetch-site".to_string(), "same-origin".to_string());
        request.add_header("sec-fetch-dest".to_string(), "document".to_string());

        let result = evaluate_early_defense(&mut request).expect("api should still drop");
        assert!(result.blocked);
        assert_eq!(
            request.get_metadata("early_defense.reason").unwrap(),
            "l4_high_risk_runtime_pressure"
        );
    }
}
