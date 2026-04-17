use super::super::{BlockedIpEntry, BlockedIpRecord, SecurityEventRecord};
use anyhow::Result;
use sha2::{Digest, Sha256};

pub(crate) fn fingerprint_security_event(event: &SecurityEventRecord) -> String {
    let mut hasher = Sha256::new();
    hasher.update(event.layer.as_bytes());
    hasher.update([0]);
    hasher.update(event.provider.as_deref().unwrap_or_default().as_bytes());
    hasher.update([0]);
    hasher.update(
        event
            .provider_event_id
            .as_deref()
            .unwrap_or_default()
            .as_bytes(),
    );
    hasher.update([0]);
    hasher.update(
        event
            .provider_site_id
            .as_deref()
            .unwrap_or_default()
            .as_bytes(),
    );
    hasher.update([0]);
    hasher.update(event.action.as_bytes());
    hasher.update([0]);
    hasher.update(event.reason.as_bytes());
    hasher.update([0]);
    hasher.update(event.details_json.as_deref().unwrap_or_default().as_bytes());
    hasher.update([0]);
    hasher.update(event.source_ip.as_bytes());
    hasher.update([0]);
    hasher.update(event.dest_ip.as_bytes());
    hasher.update([0]);
    hasher.update(event.source_port.to_le_bytes());
    hasher.update(event.dest_port.to_le_bytes());
    hasher.update([0]);
    hasher.update(event.protocol.as_bytes());
    hasher.update([0]);
    hasher.update(event.http_method.as_deref().unwrap_or_default().as_bytes());
    hasher.update([0]);
    hasher.update(event.uri.as_deref().unwrap_or_default().as_bytes());
    hasher.update([0]);
    hasher.update(event.http_version.as_deref().unwrap_or_default().as_bytes());
    hasher.update([0]);
    hasher.update(event.created_at.to_le_bytes());
    format!("{:x}", hasher.finalize())
}

pub(crate) fn serialize_string_vec(values: &[String]) -> Result<String> {
    Ok(serde_json::to_string(values)?)
}

pub(crate) fn fingerprint_blocked_ip(record: &BlockedIpEntry) -> String {
    let mut hasher = Sha256::new();
    hasher.update(record.provider.as_deref().unwrap_or_default().as_bytes());
    hasher.update([0]);
    hasher.update(
        record
            .provider_remote_id
            .as_deref()
            .unwrap_or_default()
            .as_bytes(),
    );
    hasher.update([0]);
    hasher.update(record.ip.as_bytes());
    hasher.update([0]);
    hasher.update(record.reason.as_bytes());
    hasher.update([0]);
    hasher.update(record.blocked_at.to_le_bytes());
    hasher.update(record.expires_at.to_le_bytes());
    format!("{:x}", hasher.finalize())
}

pub(crate) fn fingerprint_blocked_ip_record(record: &BlockedIpRecord) -> String {
    let mut hasher = Sha256::new();
    hasher.update(record.provider.as_deref().unwrap_or_default().as_bytes());
    hasher.update([0]);
    hasher.update(
        record
            .provider_remote_id
            .as_deref()
            .unwrap_or_default()
            .as_bytes(),
    );
    hasher.update([0]);
    hasher.update(record.ip.as_bytes());
    hasher.update([0]);
    hasher.update(record.reason.as_bytes());
    hasher.update([0]);
    hasher.update(record.blocked_at.to_le_bytes());
    hasher.update(record.expires_at.to_le_bytes());
    format!("{:x}", hasher.finalize())
}
