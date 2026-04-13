use super::*;
use sha2::{Digest, Sha256};

pub(super) struct SyncInsertState {
    pub(super) inserted: bool,
    pub(super) local_id: i64,
}

pub(super) struct CertificateSyncMetadataUpdate {
    pub(super) provider_remote_id: Option<String>,
    pub(super) provider_remote_domains: Vec<String>,
    pub(super) last_remote_fingerprint: Option<String>,
    pub(super) sync_status: String,
    pub(super) sync_message: String,
    pub(super) last_synced_at: Option<i64>,
}

pub(super) struct RemoteCertificateMatchResult {
    pub(super) remote_id: Option<String>,
    pub(super) remote_domains: Vec<String>,
    pub(super) strategy: &'static str,
}

impl RemoteCertificateMatchResult {
    pub(super) fn success_message(&self, remote_id: &str) -> String {
        match self.strategy {
            "remote_id" => format!("已按雷池证书 ID 命中并更新远端证书 {}。", remote_id),
            "domains" => format!("已按域名匹配并更新远端证书 {}。", remote_id),
            _ => format!("已在雷池创建新证书 {}。", remote_id),
        }
    }
}

pub(super) async fn sync_remote_certificate(
    store: &SqliteStore,
    local_certificates: &mut Vec<LocalCertificateEntry>,
    certificate: &SafeLineCertificateSummary,
    detail: Option<SafeLineCertificateDetail>,
    now: i64,
) -> Result<SyncInsertState> {
    let upsert = LocalCertificateUpsert {
        name: certificate
            .domains
            .first()
            .cloned()
            .unwrap_or_else(|| format!("safeline-cert-{}", certificate.id)),
        domains: certificate.domains.clone(),
        issuer: certificate.issuer.clone(),
        valid_from: certificate.valid_from,
        valid_to: certificate.valid_to,
        source_type: "safeline".to_string(),
        provider_remote_id: Some(certificate.id.clone()),
        provider_remote_domains: certificate.domains.clone(),
        last_remote_fingerprint: detail
            .as_ref()
            .and_then(|item| item.certificate_pem.as_deref())
            .and_then(certificate_fingerprint),
        sync_status: "synced".to_string(),
        sync_message: "已从雷池同步证书元数据".to_string(),
        auto_sync_enabled: false,
        trusted: certificate.trusted,
        expired: certificate.expired || certificate.revoked,
        notes: "Imported from SafeLine".to_string(),
        last_synced_at: Some(now),
    };

    let existing = local_certificates
        .iter()
        .find(|item| item.provider_remote_id.as_deref() == Some(certificate.id.as_str()))
        .cloned();

    let (local_id, inserted) = if let Some(existing) = existing {
        store.update_local_certificate(existing.id, &upsert).await?;
        replace_local_certificate(local_certificates, existing.id, &upsert, now);
        (existing.id, false)
    } else {
        let local_id = store.insert_local_certificate(&upsert).await?;
        local_certificates.push(LocalCertificateEntry {
            id: local_id,
            name: upsert.name.clone(),
            domains_json: serde_json::to_string(&upsert.domains)?,
            issuer: upsert.issuer.clone(),
            valid_from: upsert.valid_from,
            valid_to: upsert.valid_to,
            source_type: upsert.source_type.clone(),
            provider_remote_id: upsert.provider_remote_id.clone(),
            provider_remote_domains_json: serde_json::to_string(&upsert.provider_remote_domains)?,
            last_remote_fingerprint: upsert.last_remote_fingerprint.clone(),
            sync_status: upsert.sync_status.clone(),
            sync_message: upsert.sync_message.clone(),
            auto_sync_enabled: upsert.auto_sync_enabled,
            trusted: upsert.trusted,
            expired: upsert.expired,
            notes: upsert.notes.clone(),
            last_synced_at: upsert.last_synced_at,
            created_at: now,
            updated_at: now,
        });
        (local_id, true)
    };

    if let Some(detail) = detail {
        if let Some(certificate_pem) = detail.certificate_pem.as_deref() {
            if !certificate_pem.trim().is_empty() {
                store
                    .upsert_local_certificate_secret(
                        local_id,
                        certificate_pem,
                        detail.private_key_pem.as_deref().unwrap_or_default(),
                    )
                    .await?;
            }
        }
    }

    Ok(SyncInsertState { inserted, local_id })
}

pub(super) fn normalized_domain_set(domains: &[String]) -> Vec<String> {
    let mut items = domains
        .iter()
        .map(|item| item.trim().to_ascii_lowercase())
        .filter(|item| !item.is_empty())
        .collect::<Vec<_>>();
    items.sort();
    items.dedup();
    items
}

pub(super) fn certificate_fingerprint(certificate_pem: &str) -> Option<String> {
    let normalized = certificate_pem.trim();
    if normalized.is_empty() {
        return None;
    }

    let mut hasher = Sha256::new();
    hasher.update(normalized.as_bytes());
    Some(format!("{:x}", hasher.finalize()))
}

pub(super) fn match_remote_certificate(
    local_certificate: &LocalCertificateEntry,
    local_domains: &[String],
    remote_certificates: &[SafeLineCertificateSummary],
) -> Result<RemoteCertificateMatchResult> {
    let normalized_local_domains = normalized_domain_set(local_domains);

    if let Some(remote_id) = local_certificate.provider_remote_id.as_deref() {
        if let Some(remote) = remote_certificates.iter().find(|item| item.id == remote_id) {
            let normalized_remote_domains = normalized_domain_set(&remote.domains);
            if normalized_remote_domains == normalized_local_domains {
                return Ok(RemoteCertificateMatchResult {
                    remote_id: Some(remote.id.clone()),
                    remote_domains: remote.domains.clone(),
                    strategy: "remote_id",
                });
            }

            bail!(
                "本地证书 #{} 绑定的雷池证书 {} 仍存在，但域名集合已漂移。本地域名：{}；远端域名：{}。请先人工确认后再同步。",
                local_certificate.id,
                remote.id,
                normalized_local_domains.join(", "),
                normalized_remote_domains.join(", ")
            );
        }
    }

    let domain_matches = remote_certificates
        .iter()
        .filter(|item| normalized_domain_set(&item.domains) == normalized_local_domains)
        .collect::<Vec<_>>();

    if domain_matches.len() == 1 {
        let remote = domain_matches[0];
        return Ok(RemoteCertificateMatchResult {
            remote_id: Some(remote.id.clone()),
            remote_domains: remote.domains.clone(),
            strategy: "domains",
        });
    }

    if domain_matches.len() > 1 {
        bail!(
            "雷池中存在多张域名集合相同的证书（{}），当前无法自动判断应覆盖哪一张，请先人工处理。",
            normalized_local_domains.join(", ")
        );
    }

    Ok(RemoteCertificateMatchResult {
        remote_id: None,
        remote_domains: Vec::new(),
        strategy: "create",
    })
}

pub(super) async fn update_certificate_sync_metadata(
    store: &SqliteStore,
    certificate: &LocalCertificateEntry,
    metadata: CertificateSyncMetadataUpdate,
) -> Result<()> {
    let upsert = LocalCertificateUpsert {
        name: certificate.name.clone(),
        domains: parse_json_vec(&certificate.domains_json)?,
        issuer: certificate.issuer.clone(),
        valid_from: certificate.valid_from,
        valid_to: certificate.valid_to,
        source_type: certificate.source_type.clone(),
        provider_remote_id: metadata.provider_remote_id,
        provider_remote_domains: metadata.provider_remote_domains,
        last_remote_fingerprint: metadata.last_remote_fingerprint,
        sync_status: metadata.sync_status,
        sync_message: metadata.sync_message,
        auto_sync_enabled: certificate.auto_sync_enabled,
        trusted: certificate.trusted,
        expired: certificate.expired,
        notes: certificate.notes.clone(),
        last_synced_at: metadata.last_synced_at,
    };
    store
        .update_local_certificate(certificate.id, &upsert)
        .await?;
    Ok(())
}

fn replace_local_certificate(
    local_certificates: &mut [LocalCertificateEntry],
    id: i64,
    upsert: &LocalCertificateUpsert,
    now: i64,
) {
    if let Some(item) = local_certificates.iter_mut().find(|item| item.id == id) {
        item.name = upsert.name.clone();
        item.domains_json =
            serde_json::to_string(&upsert.domains).unwrap_or_else(|_| "[]".to_string());
        item.issuer = upsert.issuer.clone();
        item.valid_from = upsert.valid_from;
        item.valid_to = upsert.valid_to;
        item.source_type = upsert.source_type.clone();
        item.provider_remote_id = upsert.provider_remote_id.clone();
        item.provider_remote_domains_json = serde_json::to_string(&upsert.provider_remote_domains)
            .unwrap_or_else(|_| "[]".to_string());
        item.last_remote_fingerprint = upsert.last_remote_fingerprint.clone();
        item.sync_status = upsert.sync_status.clone();
        item.sync_message = upsert.sync_message.clone();
        item.auto_sync_enabled = upsert.auto_sync_enabled;
        item.trusted = upsert.trusted;
        item.expired = upsert.expired;
        item.notes = upsert.notes.clone();
        item.last_synced_at = upsert.last_synced_at;
        item.updated_at = now;
    }
}
