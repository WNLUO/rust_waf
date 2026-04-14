use super::*;

pub(super) fn refresh_score_and_risk(bucket: &mut BucketRuntime, unix_now: i64) {
    let recent_connections = bucket.recent_connections.len() as f64;
    let recent_requests = bucket.recent_requests.len() as f64;
    let recent_feedback = bucket.recent_feedback.len() as f64;
    let requests_per_connection = if bucket.total_connections == 0 {
        0.0
    } else {
        bucket.total_requests as f64 / bucket.total_connections as f64
    };
    let active_connections = f64::from(bucket.active_connections);
    let short_lifetime_penalty = if bucket.peer_kind == BucketPeerKind::TrustedProxy {
        0.0
    } else if bucket.avg_connection_lifetime_ms > 0.0 && bucket.avg_connection_lifetime_ms < 1500.0
    {
        12.0
    } else {
        0.0
    };
    let connection_weight = match bucket.peer_kind {
        BucketPeerKind::TrustedProxy => 0.6,
        BucketPeerKind::DirectClient => 1.8,
    };
    let request_weight = match bucket.peer_kind {
        BucketPeerKind::TrustedProxy => 0.6,
        BucketPeerKind::DirectClient => 1.0,
    };
    let feedback_weight = match bucket.peer_kind {
        BucketPeerKind::TrustedProxy => 4.0,
        BucketPeerKind::DirectClient => 18.0,
    };
    let active_weight = match bucket.peer_kind {
        BucketPeerKind::TrustedProxy => 1.5,
        BucketPeerKind::DirectClient => 6.0,
    };
    let low_rpc_penalty = if bucket.peer_kind == BucketPeerKind::TrustedProxy {
        0.0
    } else if requests_per_connection < 1.2 && bucket.total_connections > 10 {
        12.0
    } else {
        0.0
    };
    let authority_penalty = if bucket.peer_kind == BucketPeerKind::TrustedProxy {
        0.0
    } else if bucket.authority_unknown() {
        6.0
    } else {
        0.0
    };
    let enforcement_feedback = if bucket.l7_block_hits + bucket.safeline_hits > 0 {
        let score = (((bucket.l7_block_hits + bucket.safeline_hits) as f64
            / bucket.total_requests.max(1) as f64)
            * 100.0)
            .min(20.0);
        match bucket.peer_kind {
            BucketPeerKind::TrustedProxy => score.min(5.0),
            BucketPeerKind::DirectClient => score,
        }
    } else {
        0.0
    };

    let raw_score = (recent_connections * connection_weight)
        + (recent_requests * request_weight)
        + (recent_feedback * feedback_weight)
        + (active_connections * active_weight)
        + low_rpc_penalty
        + short_lifetime_penalty
        + authority_penalty
        + enforcement_feedback;

    let next_score = (bucket.score_ewma * 0.7) + (raw_score.min(100.0) * 0.3);
    bucket.score_ewma = next_score;

    let suspicious_threshold = match bucket.peer_kind {
        BucketPeerKind::TrustedProxy => 50.0,
        BucketPeerKind::DirectClient => 30.0,
    };
    let high_threshold = match bucket.peer_kind {
        BucketPeerKind::TrustedProxy => 85.0,
        BucketPeerKind::DirectClient => 70.0,
    };
    let suspicious_decay_threshold = match bucket.peer_kind {
        BucketPeerKind::TrustedProxy => 30.0,
        BucketPeerKind::DirectClient => 18.0,
    };
    let high_decay_threshold = match bucket.peer_kind {
        BucketPeerKind::TrustedProxy => 60.0,
        BucketPeerKind::DirectClient => 50.0,
    };

    let next_risk = match bucket.risk_level {
        L4BucketRiskLevel::Normal => {
            if next_score >= high_threshold {
                L4BucketRiskLevel::High
            } else if next_score >= suspicious_threshold {
                L4BucketRiskLevel::Suspicious
            } else {
                L4BucketRiskLevel::Normal
            }
        }
        L4BucketRiskLevel::Suspicious => {
            if bucket.cooldown_until > unix_now {
                L4BucketRiskLevel::Suspicious
            } else if next_score >= high_threshold {
                L4BucketRiskLevel::High
            } else if next_score <= suspicious_decay_threshold {
                L4BucketRiskLevel::Normal
            } else {
                L4BucketRiskLevel::Suspicious
            }
        }
        L4BucketRiskLevel::High => {
            if bucket.cooldown_until > unix_now {
                L4BucketRiskLevel::High
            } else if next_score <= high_decay_threshold {
                L4BucketRiskLevel::Suspicious
            } else {
                L4BucketRiskLevel::High
            }
        }
    };

    if next_risk != bucket.risk_level {
        bucket.risk_level = next_risk;
        bucket.state_since = unix_now;
        bucket.cooldown_until = unix_now + COOL_DOWN_SECS;
    }
}

pub(super) fn policy_from_runtime(
    bucket: &BucketRuntime,
    overload_level: L4OverloadLevel,
    tuning: &L4BehaviorTuning,
) -> L4AdaptivePolicy {
    let mut budget = match bucket.risk_level {
        L4BucketRiskLevel::Normal => tuning.normal_connection_budget_per_minute,
        L4BucketRiskLevel::Suspicious => tuning.suspicious_connection_budget_per_minute,
        L4BucketRiskLevel::High => tuning.high_risk_connection_budget_per_minute,
    };
    if bucket.peer_kind == BucketPeerKind::TrustedProxy {
        budget = budget.saturating_mul(4);
    }
    let mut delay_ms = 0u64;
    match overload_level {
        L4OverloadLevel::High => {
            budget = scale_budget(budget, tuning.high_overload_budget_scale_percent);
            delay_ms = tuning.high_overload_delay_ms;
        }
        L4OverloadLevel::Critical => {
            budget = scale_budget(budget, tuning.critical_overload_budget_scale_percent);
            delay_ms = tuning.critical_overload_delay_ms;
        }
        L4OverloadLevel::Normal => {}
    }

    if exceeds_threshold(
        bucket.active_connections,
        budget,
        tuning.soft_delay_threshold_percent,
    ) {
        delay_ms = delay_ms.max(tuning.soft_delay_ms);
    }
    if exceeds_threshold(
        bucket.active_connections,
        budget,
        tuning.hard_delay_threshold_percent,
    ) {
        delay_ms = delay_ms.max(tuning.hard_delay_ms);
    }
    let reject_new_connections = exceeds_threshold(
        bucket.active_connections,
        budget,
        tuning.reject_threshold_percent,
    ) || (matches!(overload_level, L4OverloadLevel::Critical)
        && exceeds_threshold(
            bucket.active_connections,
            budget,
            tuning.critical_reject_threshold_percent,
        ));
    let trusted_proxy = bucket.peer_kind == BucketPeerKind::TrustedProxy;
    let reject_new_connections = if trusted_proxy {
        false
    } else {
        reject_new_connections
    };
    let mut disable_keepalive = !matches!(bucket.risk_level, L4BucketRiskLevel::Normal);
    let mut prefer_early_close = !matches!(bucket.risk_level, L4BucketRiskLevel::Normal);

    if trusted_proxy {
        let proxy_pressure = bucket.active_connections >= budget.max(1)
            || matches!(
                overload_level,
                L4OverloadLevel::High | L4OverloadLevel::Critical
            )
            || !matches!(bucket.risk_level, L4BucketRiskLevel::Normal);
        if proxy_pressure {
            disable_keepalive = true;
            prefer_early_close = true;
        }

        delay_ms = match bucket.risk_level {
            L4BucketRiskLevel::Normal => delay_ms,
            L4BucketRiskLevel::Suspicious => delay_ms.max(tuning.soft_delay_ms.max(20)),
            L4BucketRiskLevel::High => delay_ms.max(tuning.hard_delay_ms.max(45)),
        };

        delay_ms = match overload_level {
            L4OverloadLevel::Normal => delay_ms,
            L4OverloadLevel::High => delay_ms.max(tuning.high_overload_delay_ms.max(25)),
            L4OverloadLevel::Critical => delay_ms.max(tuning.critical_overload_delay_ms.max(60)),
        };
    }

    L4AdaptivePolicy {
        risk_level: bucket.risk_level.clone(),
        risk_score: bucket.score_ewma.round().clamp(0.0, 100.0) as u32,
        disable_keepalive,
        prefer_early_close,
        reject_new_connections,
        connection_budget_per_minute: budget.max(5),
        suggested_delay_ms: delay_ms,
    }
}

pub(super) fn policy_snapshot(policy: &L4AdaptivePolicy) -> L4BucketPolicySnapshot {
    L4BucketPolicySnapshot {
        connection_budget_per_minute: policy.connection_budget_per_minute,
        shrink_idle_timeout: policy.prefer_early_close,
        disable_keepalive: policy.disable_keepalive,
        prefer_early_close: policy.prefer_early_close,
        reject_new_connections: policy.reject_new_connections,
        mode: match policy.risk_level {
            L4BucketRiskLevel::Normal => "pass".to_string(),
            L4BucketRiskLevel::Suspicious => "degrade".to_string(),
            L4BucketRiskLevel::High => "tighten".to_string(),
        },
        suggested_delay_ms: policy.suggested_delay_ms,
    }
}

pub(super) fn default_policy(
    overload_level: L4OverloadLevel,
    tuning: &L4BehaviorTuning,
) -> L4AdaptivePolicy {
    let suggested_delay_ms = match overload_level {
        L4OverloadLevel::Critical => tuning.critical_overload_delay_ms.max(tuning.soft_delay_ms),
        L4OverloadLevel::High => (tuning.high_overload_delay_ms / 2).max(5),
        L4OverloadLevel::Normal => 0,
    };
    L4AdaptivePolicy {
        risk_level: L4BucketRiskLevel::Normal,
        risk_score: 0,
        disable_keepalive: false,
        prefer_early_close: false,
        reject_new_connections: false,
        connection_budget_per_minute: tuning.normal_connection_budget_per_minute,
        suggested_delay_ms,
    }
}

pub(super) fn derive_overload_level(
    bucket_count: usize,
    max_buckets: usize,
    blocked_connections: u64,
    active_connections: u64,
    fallback_threshold: usize,
    dropped_events: u64,
    tuning: &L4BehaviorTuning,
) -> L4OverloadLevel {
    if bucket_count >= max_buckets || dropped_events >= tuning.event_drop_critical_threshold {
        return L4OverloadLevel::Critical;
    }
    if bucket_count >= fallback_threshold
        || blocked_connections >= tuning.overload_blocked_connections_threshold
        || active_connections >= tuning.overload_active_connections_threshold
    {
        return L4OverloadLevel::High;
    }
    L4OverloadLevel::Normal
}

fn scale_budget(base: u32, scale_percent: u8) -> u32 {
    ((u64::from(base) * u64::from(scale_percent)) / 100).max(1) as u32
}

fn exceeds_threshold(active_connections: u32, budget: u32, threshold_percent: u16) -> bool {
    let limit = (u64::from(budget.max(1)) * u64::from(threshold_percent)) / 100;
    u64::from(active_connections) > limit.max(1)
}

pub(super) fn overload_reason(
    overload: L4OverloadLevel,
    blocked_connections: u64,
    active_connections: u64,
    bucket_count: usize,
    max_buckets: usize,
) -> Option<String> {
    match overload {
        L4OverloadLevel::Normal => None,
        L4OverloadLevel::High => Some(format!(
            "bucket_pressure={} blocked_connections={} active_connections={}",
            bucket_count, blocked_connections, active_connections
        )),
        L4OverloadLevel::Critical => Some(format!(
            "critical_pressure bucket_count={} max_buckets={}",
            bucket_count, max_buckets
        )),
    }
}

pub(super) fn canonicalize_authority(authority: Option<&str>) -> String {
    let raw = authority
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("*");
    let host = raw
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or(raw)
        .trim();
    if host.is_empty() {
        return "*".to_string();
    }
    let without_port = if host.starts_with('[') {
        host.split(']')
            .next()
            .map(|value| format!("{value}]"))
            .unwrap_or_else(|| host.to_string())
    } else {
        host.split(':').next().unwrap_or(host).to_string()
    };
    without_port.to_ascii_lowercase()
}

pub(super) fn canonicalize_alpn(alpn: Option<&str>) -> BucketAlpn {
    match alpn
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("unknown")
        .to_ascii_lowercase()
        .as_str()
    {
        "h2" => BucketAlpn::H2,
        "h3" => BucketAlpn::H3,
        "http/1.1" | "http1.1" | "http/1" => BucketAlpn::Http11,
        _ => BucketAlpn::Unknown,
    }
}

pub(super) fn canonicalize_transport(transport: &str) -> BucketTransport {
    match transport.trim().to_ascii_lowercase().as_str() {
        "http" => BucketTransport::Http,
        "tls" | "https" => BucketTransport::Tls,
        "udp" | "quic" => BucketTransport::Udp,
        _ => BucketTransport::Unknown,
    }
}

pub(super) fn risk_label(risk: &L4BucketRiskLevel) -> &'static str {
    match risk {
        L4BucketRiskLevel::Normal => "normal",
        L4BucketRiskLevel::Suspicious => "suspicious",
        L4BucketRiskLevel::High => "high",
    }
}

pub(super) fn resolve_request_bucket_ip(
    packet: &PacketInfo,
    request: &UnifiedHttpRequest,
) -> IpAddr {
    request
        .client_ip
        .as_deref()
        .and_then(|value| value.parse::<IpAddr>().ok())
        .unwrap_or(packet.source_ip)
}

pub(super) fn max_risk_level(
    current: &L4BucketRiskLevel,
    next: &L4BucketRiskLevel,
) -> L4BucketRiskLevel {
    match (current, next) {
        (L4BucketRiskLevel::High, _) | (_, L4BucketRiskLevel::High) => L4BucketRiskLevel::High,
        (L4BucketRiskLevel::Suspicious, _) | (_, L4BucketRiskLevel::Suspicious) => {
            L4BucketRiskLevel::Suspicious
        }
        _ => L4BucketRiskLevel::Normal,
    }
}

pub(super) fn transport_label(transport: BucketTransport) -> &'static str {
    match transport {
        BucketTransport::Http => "http",
        BucketTransport::Tls => "tls",
        BucketTransport::Udp => "udp",
        BucketTransport::Unknown => "unknown",
    }
}

impl Hash for L4OverloadLevel {
    fn hash<H: Hasher>(&self, state: &mut H) {
        std::mem::discriminant(self).hash(state);
    }
}
