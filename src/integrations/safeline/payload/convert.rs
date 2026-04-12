use super::*;

impl From<SafeLineSecurityEventSummary> for SecurityEventRecord {
    fn from(value: SafeLineSecurityEventSummary) -> Self {
        Self {
            layer: "safeline".to_string(),
            provider: Some("safeline".to_string()),
            provider_event_id: None,
            provider_site_id: value.provider_site_id,
            provider_site_name: value.provider_site_name,
            provider_site_domain: value.provider_site_domain,
            action: value.action,
            reason: value.reason,
            details_json: None,
            source_ip: value.source_ip,
            dest_ip: value.dest_ip,
            source_port: value.source_port,
            dest_port: value.dest_port,
            protocol: value.protocol,
            http_method: value.http_method,
            uri: value.uri,
            http_version: value.http_version,
            created_at: value.created_at,
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
