pub(crate) async fn maybe_delay_request(request: &crate::protocol::UnifiedHttpRequest) {
    if request
        .get_metadata("runtime.pressure.drop_delay")
        .map(|value| value == "true")
        .unwrap_or(false)
    {
        return;
    }
    let delay_ms = request
        .get_metadata("l4.suggested_delay_ms")
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0);
    if delay_ms > 0 {
        tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
    }
}

pub(crate) fn peer_is_configured_trusted_proxy(
    context: &crate::core::WafContext,
    peer_ip: std::net::IpAddr,
) -> bool {
    context
        .config_snapshot()
        .effective_trusted_proxy_cidrs()
        .iter()
        .filter_map(|cidr| cidr.parse::<ipnet::IpNet>().ok())
        .any(|network| network.contains(&peer_ip))
}

pub(crate) fn should_skip_l4_connection_budget_for_trusted_proxy(
    context: &crate::core::WafContext,
    peer_ip: std::net::IpAddr,
) -> bool {
    let config = context.config_snapshot();
    if matches!(
        config.gateway_config.source_ip_strategy,
        crate::config::SourceIpStrategy::Connection
    ) {
        return false;
    }

    peer_is_configured_trusted_proxy(context, peer_ip)
}

pub(crate) async fn maybe_delay_policy(
    context: &crate::core::WafContext,
    policy: &crate::l4::behavior::L4AdaptivePolicy,
) {
    if context.runtime_pressure_snapshot().drop_delay {
        return;
    }
    if policy.suggested_delay_ms > 0 {
        tokio::time::sleep(std::time::Duration::from_millis(policy.suggested_delay_ms)).await;
    }
}

pub(crate) fn soften_explicit_response_for_runtime(
    context: &crate::core::WafContext,
    response: &crate::core::CustomHttpResponse,
) -> crate::core::CustomHttpResponse {
    let mut resolved = response.clone();
    if context.runtime_pressure_snapshot().drop_delay && resolved.tarpit.is_some() {
        resolved.tarpit = None;
        resolved.headers.push((
            "x-rust-waf-runtime-degrade".to_string(),
            "response_tarpit_disabled_under_runtime_pressure".to_string(),
        ));
    }
    resolved
}

pub(crate) fn record_l7_cc_metrics(
    metrics: &crate::metrics::MetricsCollector,
    request: &crate::protocol::UnifiedHttpRequest,
) {
    let unresolved_identity = request
        .get_metadata("l7.cc.client_identity_unresolved")
        .map(|value| value == "true")
        .unwrap_or(false);
    if request
        .get_metadata("l7.cc.challenge_verified")
        .map(|value| value == "true")
        .unwrap_or(false)
    {
        metrics.record_l7_cc_verified_pass();
    }

    match request.get_metadata("l7.cc.action").map(String::as_str) {
        Some("challenge") => metrics.record_l7_cc_challenge(),
        Some("block") => metrics.record_l7_cc_block(),
        Some(action) if action.starts_with("delay:") => {
            metrics.record_l7_cc_delay();
            if unresolved_identity {
                metrics.record_l7_cc_unresolved_identity_delay();
            }
        }
        _ => {}
    }
}

pub(crate) fn record_l7_behavior_metrics(
    metrics: &crate::metrics::MetricsCollector,
    request: &crate::protocol::UnifiedHttpRequest,
) {
    match request
        .get_metadata("l7.behavior.action")
        .map(String::as_str)
    {
        Some("challenge") => metrics.record_l7_behavior_challenge(),
        Some("block") => metrics.record_l7_behavior_block(),
        Some(action) if action.starts_with("delay:") => metrics.record_l7_behavior_delay(),
        _ => {}
    }
}

pub(crate) fn proxy_traffic_kind(
    request: &crate::protocol::UnifiedHttpRequest,
) -> crate::metrics::ProxyTrafficKind {
    match request
        .get_metadata("l7.cc.request_kind")
        .map(String::as_str)
    {
        Some("document") => crate::metrics::ProxyTrafficKind::Document,
        Some("api") => crate::metrics::ProxyTrafficKind::Api,
        Some("static") => crate::metrics::ProxyTrafficKind::Static,
        _ => crate::metrics::ProxyTrafficKind::Other,
    }
}

pub(crate) fn proxy_metric_labels(
    request: &crate::protocol::UnifiedHttpRequest,
) -> crate::metrics::ProxyMetricLabels {
    crate::metrics::ProxyMetricLabels {
        host: request
            .get_metadata("l7.cc.host")
            .cloned()
            .unwrap_or_else(|| "unknown-host".to_string()),
        route: request
            .get_metadata("l7.cc.route")
            .cloned()
            .unwrap_or_else(|| "unknown-route".to_string()),
        request_kind: request
            .get_metadata("l7.cc.request_kind")
            .cloned()
            .unwrap_or_else(|| "other".to_string()),
    }
}

pub(crate) fn request_in_critical_overload(request: &crate::protocol::UnifiedHttpRequest) -> bool {
    request
        .get_metadata("l4.overload_level")
        .map(|value| value == "critical")
        .unwrap_or(false)
}

pub(crate) fn next_connection_id(
    peer_addr: std::net::SocketAddr,
    local_addr: std::net::SocketAddr,
    transport: &str,
) -> String {
    static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let id = NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    format!("{transport}-{peer_addr}-{local_addr}-{id}")
}
