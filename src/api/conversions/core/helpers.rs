use super::*;

pub(super) fn display_https_listen_port(value: &str) -> String {
    value
        .trim()
        .parse::<SocketAddr>()
        .map(|addr| addr.port().to_string())
        .unwrap_or_else(|_| value.trim().to_string())
}

pub(super) fn normalize_https_listen_addr_input(value: &str) -> Result<String, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(String::new());
    }

    if let Ok(port) = trimmed.parse::<u16>() {
        if port == 0 {
            return Err("HTTPS 入口端口不能为 0".to_string());
        }
        return Ok(format!("0.0.0.0:{port}"));
    }

    let addr = trimmed
        .parse::<SocketAddr>()
        .map_err(|err| format!("HTTPS 入口 '{}' 无效: {}", trimmed, err))?;
    if addr.port() == 0 {
        return Err("HTTPS 入口端口不能为 0".to_string());
    }

    Ok(format!("0.0.0.0:{}", addr.port()))
}

pub(super) fn source_ip_strategy_label(strategy: SourceIpStrategy) -> &'static str {
    match strategy {
        SourceIpStrategy::Connection => "connection",
        SourceIpStrategy::XForwardedForFirst => "x_forwarded_for_first",
        SourceIpStrategy::XForwardedForLast => "x_forwarded_for_last",
        SourceIpStrategy::XForwardedForLastButOne => "x_forwarded_for_last_but_one",
        SourceIpStrategy::XForwardedForLastButTwo => "x_forwarded_for_last_but_two",
        SourceIpStrategy::Header => "header",
        SourceIpStrategy::ProxyProtocol => "proxy_protocol",
    }
}

pub(super) fn parse_source_ip_strategy(value: &str) -> Result<SourceIpStrategy, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "connection" => Ok(SourceIpStrategy::Connection),
        "x_forwarded_for_first" => Ok(SourceIpStrategy::XForwardedForFirst),
        "x_forwarded_for_last" => Ok(SourceIpStrategy::XForwardedForLast),
        "x_forwarded_for_last_but_one" => Ok(SourceIpStrategy::XForwardedForLastButOne),
        "x_forwarded_for_last_but_two" => Ok(SourceIpStrategy::XForwardedForLastButTwo),
        "header" => Ok(SourceIpStrategy::Header),
        "proxy_protocol" => Ok(SourceIpStrategy::ProxyProtocol),
        other => Err(format!("源 IP 获取方式不支持 '{}'", other)),
    }
}

pub(super) fn upstream_failure_mode_label(
    mode: crate::config::l7::UpstreamFailureMode,
) -> &'static str {
    match mode {
        crate::config::l7::UpstreamFailureMode::FailOpen => "fail_open",
        crate::config::l7::UpstreamFailureMode::FailClose => "fail_close",
    }
}

pub(super) fn parse_upstream_failure_mode(
    value: &str,
) -> Result<crate::config::l7::UpstreamFailureMode, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "fail_open" => Ok(crate::config::l7::UpstreamFailureMode::FailOpen),
        "fail_close" => Ok(crate::config::l7::UpstreamFailureMode::FailClose),
        _ => Err("上游失败策略仅支持 fail_open 或 fail_close".to_string()),
    }
}

pub(super) fn upstream_protocol_policy_label(
    policy: crate::config::UpstreamProtocolPolicy,
) -> &'static str {
    match policy {
        crate::config::UpstreamProtocolPolicy::Auto => "auto",
        crate::config::UpstreamProtocolPolicy::Http1Only => "http1_only",
        crate::config::UpstreamProtocolPolicy::Http2Preferred => "http2_preferred",
        crate::config::UpstreamProtocolPolicy::Http2Only => "http2_only",
    }
}

pub(super) fn parse_upstream_protocol_policy(
    value: &str,
) -> Result<crate::config::UpstreamProtocolPolicy, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "auto" => Ok(crate::config::UpstreamProtocolPolicy::Auto),
        "http1_only" => Ok(crate::config::UpstreamProtocolPolicy::Http1Only),
        "http2_preferred" => Ok(crate::config::UpstreamProtocolPolicy::Http2Preferred),
        "http2_only" => Ok(crate::config::UpstreamProtocolPolicy::Http2Only),
        other => Err(format!(
            "上游协议策略仅支持 auto、http1_only、http2_preferred、http2_only，收到 '{}'",
            other
        )),
    }
}

pub(super) fn safeline_intercept_action_label(
    action: crate::config::l7::SafeLineInterceptAction,
) -> &'static str {
    match action {
        crate::config::l7::SafeLineInterceptAction::Pass => "pass",
        crate::config::l7::SafeLineInterceptAction::Replace => "replace",
        crate::config::l7::SafeLineInterceptAction::Drop => "drop",
        crate::config::l7::SafeLineInterceptAction::ReplaceAndBlockIp => "replace_and_block_ip",
    }
}

pub(super) fn parse_safeline_intercept_action(
    value: &str,
) -> Result<crate::config::l7::SafeLineInterceptAction, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "pass" => Ok(crate::config::l7::SafeLineInterceptAction::Pass),
        "replace" => Ok(crate::config::l7::SafeLineInterceptAction::Replace),
        "drop" => Ok(crate::config::l7::SafeLineInterceptAction::Drop),
        "replace_and_block_ip" => Ok(crate::config::l7::SafeLineInterceptAction::ReplaceAndBlockIp),
        other => Err(format!(
            "SafeLine 响应动作仅支持 pass、replace、drop、replace_and_block_ip，收到 '{}'",
            other
        )),
    }
}

pub(super) fn safeline_intercept_match_mode_label(
    mode: crate::config::l7::SafeLineInterceptMatchMode,
) -> &'static str {
    match mode {
        crate::config::l7::SafeLineInterceptMatchMode::Strict => "strict",
        crate::config::l7::SafeLineInterceptMatchMode::Relaxed => "relaxed",
    }
}

pub(super) fn parse_safeline_intercept_match_mode(
    value: &str,
) -> Result<crate::config::l7::SafeLineInterceptMatchMode, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "strict" => Ok(crate::config::l7::SafeLineInterceptMatchMode::Strict),
        "relaxed" => Ok(crate::config::l7::SafeLineInterceptMatchMode::Relaxed),
        other => Err(format!(
            "SafeLine 匹配模式仅支持 strict 或 relaxed，收到 '{}'",
            other
        )),
    }
}

pub(super) fn auto_tuning_mode_label(mode: AutoTuningMode) -> &'static str {
    match mode {
        AutoTuningMode::Off => "off",
        AutoTuningMode::Observe => "observe",
        AutoTuningMode::Active => "active",
    }
}

pub(super) fn parse_auto_tuning_mode(value: &str) -> Result<AutoTuningMode, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "off" => Ok(AutoTuningMode::Off),
        "observe" => Ok(AutoTuningMode::Observe),
        "active" => Ok(AutoTuningMode::Active),
        other => Err(format!(
            "自动调优模式仅支持 off、observe、active，收到 '{}'",
            other
        )),
    }
}

pub(super) fn auto_tuning_intent_label(intent: AutoTuningIntent) -> &'static str {
    match intent {
        AutoTuningIntent::Conservative => "conservative",
        AutoTuningIntent::Balanced => "balanced",
        AutoTuningIntent::Aggressive => "aggressive",
    }
}

pub(super) fn adaptive_protection_mode_label(
    mode: crate::config::AdaptiveProtectionMode,
) -> &'static str {
    match mode {
        crate::config::AdaptiveProtectionMode::Relaxed => "relaxed",
        crate::config::AdaptiveProtectionMode::Balanced => "balanced",
        crate::config::AdaptiveProtectionMode::Strict => "strict",
    }
}

pub(super) fn parse_adaptive_protection_mode(
    value: &str,
) -> Result<crate::config::AdaptiveProtectionMode, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "relaxed" => Ok(crate::config::AdaptiveProtectionMode::Relaxed),
        "balanced" => Ok(crate::config::AdaptiveProtectionMode::Balanced),
        "strict" => Ok(crate::config::AdaptiveProtectionMode::Strict),
        other => Err(format!(
            "自适应防护模式仅支持 relaxed、balanced、strict，收到 '{}'",
            other
        )),
    }
}

pub(super) fn adaptive_protection_goal_label(
    goal: crate::config::AdaptiveProtectionGoal,
) -> &'static str {
    match goal {
        crate::config::AdaptiveProtectionGoal::AvailabilityFirst => "availability_first",
        crate::config::AdaptiveProtectionGoal::Balanced => "balanced",
        crate::config::AdaptiveProtectionGoal::SecurityFirst => "security_first",
    }
}

pub(super) fn parse_adaptive_protection_goal(
    value: &str,
) -> Result<crate::config::AdaptiveProtectionGoal, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "availability_first" => Ok(crate::config::AdaptiveProtectionGoal::AvailabilityFirst),
        "balanced" => Ok(crate::config::AdaptiveProtectionGoal::Balanced),
        "security_first" => Ok(crate::config::AdaptiveProtectionGoal::SecurityFirst),
        other => Err(format!(
            "自适应防护目标仅支持 availability_first、balanced、security_first，收到 '{}'",
            other
        )),
    }
}

pub(super) fn parse_auto_tuning_intent(value: &str) -> Result<AutoTuningIntent, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "conservative" => Ok(AutoTuningIntent::Conservative),
        "balanced" => Ok(AutoTuningIntent::Balanced),
        "aggressive" => Ok(AutoTuningIntent::Aggressive),
        other => Err(format!(
            "自动调优强度仅支持 conservative、balanced、aggressive，收到 '{}'",
            other
        )),
    }
}

pub(super) fn trusted_cdn_sync_interval_unit_label(
    unit: crate::config::l4::TrustedCdnSyncIntervalUnit,
) -> &'static str {
    match unit {
        crate::config::l4::TrustedCdnSyncIntervalUnit::Minute => "minute",
        crate::config::l4::TrustedCdnSyncIntervalUnit::Hour => "hour",
        crate::config::l4::TrustedCdnSyncIntervalUnit::Day => "day",
    }
}

pub(super) fn parse_trusted_cdn_sync_interval_unit(
    value: &str,
) -> Result<crate::config::l4::TrustedCdnSyncIntervalUnit, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "minute" | "minutes" => Ok(crate::config::l4::TrustedCdnSyncIntervalUnit::Minute),
        "hour" | "hours" => Ok(crate::config::l4::TrustedCdnSyncIntervalUnit::Hour),
        "day" | "days" => Ok(crate::config::l4::TrustedCdnSyncIntervalUnit::Day),
        other => Err(format!("可信 CDN 同步周期单位不支持 '{}'", other)),
    }
}

pub(super) fn trusted_cdn_sync_status_label(
    status: crate::config::l4::TrustedCdnSyncStatus,
) -> &'static str {
    match status {
        crate::config::l4::TrustedCdnSyncStatus::Idle => "idle",
        crate::config::l4::TrustedCdnSyncStatus::Success => "success",
        crate::config::l4::TrustedCdnSyncStatus::Error => "error",
    }
}
