use super::*;

pub(super) fn parse_site_summary(value: &Value) -> Option<SafeLineSiteSummary> {
    let object = value.as_object()?;
    let server_names = pick_array_strings(object, &["server_names", "hosts"]).unwrap_or_default();
    let ports = pick_array_strings(object, &["ports"]).unwrap_or_default();
    let ssl_ports = ports
        .iter()
        .filter(|port| port.to_ascii_lowercase().contains("ssl"))
        .cloned()
        .collect::<Vec<_>>();
    let upstreams = pick_array_strings(object, &["upstreams"]).unwrap_or_default();
    let enabled = pick_bool(object, &["is_enabled", "enabled"]);
    let cert_id = pick_i64(object, &["cert_id"]);
    let cert_type = pick_i64(object, &["cert_type"]);
    let cert_filename = pick_string(object, &["cert_filename"]);
    let key_filename = pick_string(object, &["key_filename"]);
    let health_check = pick_bool(object, &["health_check"]);
    let id = pick_string(
        object,
        &["id", "uuid", "site_id", "siteId", "website_id", "uid"],
    )
    .unwrap_or_default();
    let name = pick_string(
        object,
        &[
            "name",
            "title",
            "comment",
            "site_name",
            "siteName",
            "domain",
            "website",
            "host",
        ],
    )
    .unwrap_or_else(|| "未命名站点".to_string());
    let domain = pick_string(
        object,
        &["domain", "hostname", "host", "server", "origin", "upstream"],
    )
    .or_else(|| server_names.first().cloned())
    .unwrap_or_default();
    let status = enabled
        .map(|value| {
            if value {
                "enabled".to_string()
            } else {
                "disabled".to_string()
            }
        })
        .or_else(|| pick_string(object, &["status", "state", "mode"]))
        .unwrap_or_else(|| "unknown".to_string());
    let ssl_enabled = !ssl_ports.is_empty()
        || cert_id.unwrap_or_default() > 0
        || cert_filename
            .as_ref()
            .map(|value| !value.trim().is_empty())
            .unwrap_or(false);

    Some(SafeLineSiteSummary {
        id,
        name,
        domain,
        status,
        enabled,
        server_names,
        ports,
        ssl_ports,
        upstreams,
        ssl_enabled,
        cert_id,
        cert_type,
        cert_filename,
        key_filename,
        health_check,
        raw: value.clone(),
    })
}

pub(super) fn parse_certificate_summary(value: &Value) -> Option<SafeLineCertificateSummary> {
    let object = value.as_object()?;
    let id = pick_string(object, &["id", "cert_id", "uuid", "uid"])?;
    let domains = pick_array_strings(object, &["domains"])
        .or_else(|| pick_array_strings(object, &["related_sites"]))
        .unwrap_or_default();

    Some(SafeLineCertificateSummary {
        id,
        domains,
        issuer: pick_string(object, &["issuer"]).unwrap_or_default(),
        trusted: pick_bool(object, &["trusted"]).unwrap_or(false),
        revoked: pick_bool(object, &["revoked"]).unwrap_or(false),
        expired: pick_bool(object, &["expired"]).unwrap_or(false),
        cert_type: pick_i64(object, &["type", "cert_type"]),
        valid_from: pick_timestamp(object, &["valid_after", "valid_from", "created_at"]),
        valid_to: pick_timestamp(object, &["valid_before", "valid_to", "expires_at"]),
        related_sites: pick_array_strings(object, &["related_sites"]).unwrap_or_default(),
        raw: value.clone(),
    })
}

pub(super) fn parse_security_event_summary(value: &Value) -> Option<SafeLineSecurityEventSummary> {
    let object = value.as_object()?;
    let source_ip = pick_string(
        object,
        &["src_ip", "source_ip", "client_ip", "ip", "remote_addr"],
    )
    .unwrap_or_else(|| "0.0.0.0".to_string());
    let dest_ip = pick_string(object, &["dst_ip", "dest_ip", "server_ip"]).unwrap_or_default();
    let raw_action = pick_string(object, &["action", "decision", "event_type", "type"]);
    let action = normalize_safeline_action(raw_action.as_deref());
    let attack_type = pick_string(object, &["attack_type", "rule_type", "category"]);
    let reason = pick_string(object, &["reason", "message", "description", "rule_name"])
        .or(attack_type.clone())
        .unwrap_or_else(|| "safeline_event".to_string());
    let uri = pick_string(object, &["uri", "path", "url", "request_uri"]);
    let http_method = pick_string(object, &["method", "http_method", "request_method"]);
    let http_version = pick_string(object, &["http_version", "version"]);
    let protocol =
        pick_string(object, &["protocol", "scheme"]).unwrap_or_else(|| "HTTP".to_string());
    let source_port = pick_i64(object, &["src_port", "source_port", "client_port"]).unwrap_or(0);
    let dest_port = pick_i64(object, &["dst_port", "dest_port", "server_port"]).unwrap_or(0);
    let created_at = pick_i64(
        object,
        &[
            "created_at",
            "timestamp",
            "time",
            "occurred_at",
            "attack_time",
        ],
    )
    .unwrap_or_else(unix_timestamp);
    let provider_site_id = pick_string(
        object,
        &["site_id", "siteId", "website_id", "websiteId", "uuid"],
    );
    let provider_site_name = pick_string(
        object,
        &[
            "site_name",
            "siteName",
            "site_title",
            "site_comment",
            "website",
            "domain_name",
            "host_name",
        ],
    );
    let provider_site_domain = pick_string(
        object,
        &[
            "domain",
            "host",
            "hostname",
            "server_name",
            "website_domain",
        ],
    )
    .or_else(|| pick_first_array_string(object, &["site_server_names", "server_names"]))
    .or_else(|| pick_string(object, &["website"]))
    .or_else(|| uri.as_ref().and_then(|value| extract_host_from_uri(value)));

    Some(SafeLineSecurityEventSummary {
        provider_site_id,
        provider_site_name,
        provider_site_domain,
        action,
        raw_action,
        reason: attack_type
            .map(|kind| format!("safeline:{kind}:{reason}"))
            .unwrap_or_else(|| format!("safeline:{reason}")),
        source_ip,
        dest_ip,
        source_port,
        dest_port,
        protocol,
        http_method,
        uri,
        http_version,
        created_at: normalize_timestamp(created_at),
        raw: value.clone(),
    })
}

fn normalize_safeline_action(raw: Option<&str>) -> String {
    match raw.unwrap_or("alert").trim().to_ascii_lowercase().as_str() {
        "1" | "block" | "blocked" | "deny" | "denied" | "forbid" | "intercept" | "intercepted"
        | "reject" | "kill" => "block".to_string(),
        "2" | "drop" | "dropped" => "drop".to_string(),
        "3" | "respond" | "captcha" | "challenge" => "respond".to_string(),
        "0" | "alert" | "detect" | "detected" | "log" | "pass" | "allow" | "allowed" => {
            "alert".to_string()
        }
        _ => "alert".to_string(),
    }
}

pub(super) fn parse_blocked_ip_summaries(value: &Value) -> Vec<SafeLineBlockedIpSummary> {
    let Some(object) = value.as_object() else {
        return Vec::new();
    };
    let Some(ips) = pick_array_strings(object, &["ips"]) else {
        return parse_flat_blocked_ip_summary(value).into_iter().collect();
    };

    let reason = pick_string(object, &["reason", "message", "description"])
        .or_else(|| pick_string(object, &["reference", "comment"]))
        .unwrap_or_else(|| "safeline_blocked_ip".to_string());
    let blocked_at = pick_timestamp(
        object,
        &[
            "blocked_at",
            "updated_at",
            "created_at",
            "timestamp",
            "time",
        ],
    )
    .unwrap_or_else(unix_timestamp);
    let expires_at = pick_timestamp(
        object,
        &["expires_at", "expired_at", "expire_at", "ttl_until"],
    )
    .unwrap_or(blocked_at + 3600);
    let remote_id = pick_string(object, &["id", "uuid", "uid"]);

    ips.into_iter()
        .map(|ip| SafeLineBlockedIpSummary {
            remote_id: remote_id.clone(),
            ip,
            reason: format!("safeline:{reason}"),
            blocked_at,
            expires_at,
            raw: value.clone(),
        })
        .collect()
}

fn parse_flat_blocked_ip_summary(value: &Value) -> Option<SafeLineBlockedIpSummary> {
    let object = value.as_object()?;
    let ip = pick_string(object, &["ip", "ip_addr", "address"])?;
    let reason = pick_string(object, &["reason", "message", "description"])
        .or_else(|| pick_string(object, &["reference", "comment"]))
        .unwrap_or_else(|| "safeline_blocked_ip".to_string());
    let blocked_at = pick_timestamp(
        object,
        &[
            "blocked_at",
            "updated_at",
            "created_at",
            "timestamp",
            "time",
        ],
    )
    .unwrap_or_else(unix_timestamp);
    let expires_at = pick_timestamp(
        object,
        &["expires_at", "expired_at", "expire_at", "ttl_until"],
    )
    .unwrap_or(blocked_at + 3600);
    let remote_id = pick_string(object, &["id", "uuid", "uid"]);

    Some(SafeLineBlockedIpSummary {
        remote_id,
        ip,
        reason: format!("safeline:{reason}"),
        blocked_at,
        expires_at,
        raw: value.clone(),
    })
}

pub(super) fn looks_like_blocked_ip_summary(value: &Value) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };

    object.contains_key("ips")
        || object.contains_key("ip")
        || object.contains_key("ip_addr")
        || object.contains_key("address")
}

pub(super) fn extract_host_from_uri(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        return reqwest::Url::parse(trimmed)
            .ok()
            .and_then(|url| url.host_str().map(|host| host.to_string()));
    }
    None
}
