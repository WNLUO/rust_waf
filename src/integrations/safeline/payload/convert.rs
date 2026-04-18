use super::*;
use serde_json::Value;

impl From<SafeLineSecurityEventSummary> for SecurityEventRecord {
    fn from(value: SafeLineSecurityEventSummary) -> Self {
        let SafeLineSecurityEventSummary {
            provider_site_id,
            provider_site_name,
            provider_site_domain,
            action,
            raw_action,
            reason,
            source_ip,
            dest_ip,
            source_port,
            dest_port,
            protocol,
            http_method,
            uri,
            http_version,
            created_at,
            raw,
        } = value;

        let identity_markers = collect_safeline_identity_markers(&raw);
        let provider_event_id = identity_markers
            .first()
            .map(|(_, value)| value.clone())
            .or_else(|| extract_string_by_keys(&raw, &["event_id", "eventId", "log_id", "id"]));
        let details_json = serde_json::to_string_pretty(&serde_json::json!({
            "provider": {
                "name": "safeline",
                "raw_action": raw_action,
                "normalized_action": action,
            },
            "raw": raw,
            "identity_markers": identity_markers
                .iter()
                .map(|(key, value)| ((*key).to_string(), value.clone()))
                .collect::<std::collections::BTreeMap<_, _>>(),
        }))
        .ok();

        Self {
            layer: "safeline".to_string(),
            provider: Some("safeline".to_string()),
            provider_event_id,
            provider_site_id,
            provider_site_name,
            provider_site_domain,
            action,
            reason,
            details_json,
            source_ip,
            dest_ip,
            source_port,
            dest_port,
            protocol,
            http_method,
            uri,
            http_version,
            created_at,
            handled: false,
            handled_at: None,
        }
    }
}

impl From<SafeLineBlockedIpSummary> for BlockedIpRecord {
    fn from(value: SafeLineBlockedIpSummary) -> Self {
        Self {
            provider: Some("safeline".to_string()),
            provider_remote_id: value.remote_id,
            ip: value.ip,
            reason: value.reason,
            blocked_at: value.blocked_at,
            expires_at: value.expires_at,
        }
    }
}

fn collect_safeline_identity_markers(raw: &Value) -> Vec<(&'static str, String)> {
    let mut markers = Vec::new();
    for (label, keys) in [
        (
            "fingerprint_id",
            &["fingerprint_id", "fingerprintId", "fingerprint"][..],
        ),
        (
            "device_id",
            &["device_id", "deviceId", "client_id", "clientId"][..],
        ),
        (
            "session_id",
            &["session_id", "sessionId", "sid", "trace_id", "traceId"][..],
        ),
    ] {
        if let Some(value) = extract_string_by_keys(raw, keys) {
            markers.push((label, value));
        }
    }
    markers
}

fn extract_string_by_keys(value: &Value, keys: &[&str]) -> Option<String> {
    match value {
        Value::Object(object) => {
            for key in keys {
                if let Some(candidate) = object.get(*key).and_then(Value::as_str) {
                    let trimmed = candidate.trim();
                    if !trimmed.is_empty() {
                        return Some(trimmed.to_string());
                    }
                }
            }
            for child in object.values() {
                if let Some(found) = extract_string_by_keys(child, keys) {
                    return Some(found);
                }
            }
            None
        }
        Value::Array(items) => {
            for item in items {
                if let Some(found) = extract_string_by_keys(item, keys) {
                    return Some(found);
                }
            }
            None
        }
        _ => None,
    }
}
