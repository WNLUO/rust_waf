mod blocklist;
mod certificates;
mod events;
mod sites;

use crate::config::SafeLineConfig;
use crate::integrations::safeline::{
    SafeLineCertificateDetail, SafeLineCertificateSummary, SafeLineCertificateUpsert,
    SafeLineSiteSummary, SafeLineSiteUpsert,
};
use crate::storage::{
    BlockedIpQuery, BlockedIpRecord, LocalCertificateEntry, LocalCertificateUpsert, LocalSiteEntry,
    LocalSiteUpsert, SafeLineBlocklistPullResult, SafeLineBlocklistSyncResult,
    SafeLineImportResult, SecurityEventRecord, SiteSyncLinkUpsert, SqliteStore,
};
use anyhow::{anyhow, bail, Result};
use sha2::{Digest, Sha256};

pub use blocklist::{pull_blocked_ips, push_blocked_ips};
pub use certificates::{preview_certificate_match, pull_certificate, pull_certificates, push_certificate};
pub use events::sync_events;
pub use sites::{pull_site, pull_sites, push_site, push_sites};

#[derive(Debug, Clone, Default)]
pub struct SafeLineSitesPullResult {
    pub imported_sites: usize,
    pub updated_sites: usize,
    pub imported_certificates: usize,
    pub updated_certificates: usize,
    pub linked_sites: usize,
    pub skipped_sites: usize,
}

#[derive(Debug, Clone, Default)]
pub struct SafeLineSitesPushResult {
    pub created_sites: usize,
    pub updated_sites: usize,
    pub created_certificates: usize,
    pub reused_certificates: usize,
    pub skipped_sites: usize,
    pub failed_sites: usize,
}

#[derive(Debug, Clone, Default)]
pub struct SafeLineCertificatesPullResult {
    pub imported_certificates: usize,
    pub updated_certificates: usize,
    pub skipped_certificates: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SingleSiteSyncAction {
    Created,
    Updated,
}

#[derive(Debug, Clone, Copy)]
pub struct SafeLineSitePullOptions {
    pub name: bool,
    pub primary_hostname: bool,
    pub hostnames: bool,
    pub listen_ports: bool,
    pub upstreams: bool,
    pub enabled: bool,
}

impl Default for SafeLineSitePullOptions {
    fn default() -> Self {
        Self {
            name: true,
            primary_hostname: true,
            hostnames: true,
            listen_ports: true,
            upstreams: true,
            enabled: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SafeLineSingleSitePullResult {
    pub action: SingleSiteSyncAction,
    pub local_site_id: i64,
    pub remote_site_id: String,
}

#[derive(Debug, Clone)]
pub struct SafeLineSingleSitePushResult {
    pub action: SingleSiteSyncAction,
    pub local_site_id: i64,
    pub remote_site_id: String,
}

fn ensure_enabled(config: &SafeLineConfig) -> Result<()> {
    if !config.enabled {
        bail!("雷池集成尚未启用");
    }
    Ok(())
}

fn apply_safeline_mapping(
    event: crate::integrations::safeline::SafeLineSecurityEventSummary,
    mappings: &[crate::storage::SafeLineSiteMappingEntry],
) -> SecurityEventRecord {
    let mut record = SecurityEventRecord::from(event);

    if let Some(mapping) = mappings
        .iter()
        .find(|mapping| matches_mapping(&record, mapping))
    {
        record.provider_site_id = Some(mapping.safeline_site_id.clone());
        record.provider_site_name = Some(mapping.local_alias.clone());
        record.provider_site_domain = Some(mapping.safeline_site_domain.clone());
    }

    record
}

fn matches_mapping(
    record: &SecurityEventRecord,
    mapping: &crate::storage::SafeLineSiteMappingEntry,
) -> bool {
    record
        .provider_site_id
        .as_deref()
        .map(|value| value == mapping.safeline_site_id)
        .unwrap_or(false)
        || record
            .provider_site_domain
            .as_deref()
            .map(|value| !value.is_empty() && value == mapping.safeline_site_domain)
            .unwrap_or(false)
        || record
            .provider_site_name
            .as_deref()
            .map(|value| !value.is_empty() && value == mapping.safeline_site_name)
            .unwrap_or(false)
}

struct SyncInsertState {
    inserted: bool,
    local_id: i64,
}

struct CertificateSyncMetadataUpdate {
    provider_remote_id: Option<String>,
    provider_remote_domains: Vec<String>,
    last_remote_fingerprint: Option<String>,
    sync_status: String,
    sync_message: String,
    last_synced_at: Option<i64>,
}

struct RemoteCertificateMatchResult {
    remote_id: Option<String>,
    remote_domains: Vec<String>,
    strategy: &'static str,
}

impl RemoteCertificateMatchResult {
    fn success_message(&self, remote_id: &str) -> String {
        match self.strategy {
            "remote_id" => format!("已按雷池证书 ID 命中并更新远端证书 {}。", remote_id),
            "domains" => format!("已按域名匹配并更新远端证书 {}。", remote_id),
            _ => format!("已在雷池创建新证书 {}。", remote_id),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CertificateMatchPreview {
    pub status: String,
    pub strategy: String,
    pub local_certificate_id: i64,
    pub local_domains: Vec<String>,
    pub linked_remote_id: Option<String>,
    pub matched_remote_id: Option<String>,
    pub message: String,
    pub candidates: Vec<SafeLineCertificateSummary>,
}

async fn sync_remote_certificate(
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

fn local_site_upsert_from_remote(
    remote_site: &SafeLineSiteSummary,
    local_certificate_id: Option<i64>,
    sync_mode: &str,
    now: i64,
) -> LocalSiteUpsert {
    let primary_hostname = remote_site
        .server_names
        .first()
        .cloned()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| remote_site.domain.clone());
    let mut hostnames = remote_site.server_names.clone();
    if !hostnames.iter().any(|item| item == &primary_hostname) {
        hostnames.insert(0, primary_hostname.clone());
    }

    LocalSiteUpsert {
        name: if !remote_site.name.trim().is_empty() {
            remote_site.name.clone()
        } else {
            primary_hostname.clone()
        },
        primary_hostname,
        hostnames,
        listen_ports: remote_site.ports.clone(),
        upstreams: remote_site.upstreams.clone(),
        safeline_intercept: None,
        enabled: remote_site
            .enabled
            .unwrap_or_else(|| !remote_site.status.contains("disabled")),
        tls_enabled: remote_site.ssl_enabled,
        local_certificate_id,
        source: "safeline".to_string(),
        sync_mode: sync_mode.to_string(),
        notes: format!("Imported from SafeLine site {}", remote_site.id),
        last_synced_at: Some(now),
    }
}

fn merge_local_site_upsert_from_remote(
    remote_site: &SafeLineSiteSummary,
    local_certificate_id: Option<i64>,
    sync_mode: &str,
    now: i64,
    existing_site: Option<&LocalSiteEntry>,
    options: SafeLineSitePullOptions,
) -> LocalSiteUpsert {
    let remote_upsert =
        local_site_upsert_from_remote(remote_site, local_certificate_id, sync_mode, now);

    let mut merged = if let Some(existing_site) = existing_site {
        let mut hostnames = if options.hostnames {
            remote_upsert.hostnames.clone()
        } else {
            parse_json_vec(&existing_site.hostnames_json)
                .unwrap_or_else(|_| vec![existing_site.primary_hostname.clone()])
        };

        let primary_hostname = if options.primary_hostname {
            remote_upsert.primary_hostname.clone()
        } else {
            existing_site.primary_hostname.clone()
        };

        if !hostnames.iter().any(|item| item == &primary_hostname) {
            hostnames.insert(0, primary_hostname.clone());
        }

        LocalSiteUpsert {
            name: if options.name {
                remote_upsert.name.clone()
            } else {
                existing_site.name.clone()
            },
            primary_hostname,
            hostnames,
            listen_ports: if options.listen_ports {
                remote_upsert.listen_ports.clone()
            } else {
                parse_json_vec(&existing_site.listen_ports_json).unwrap_or_default()
            },
            upstreams: if options.upstreams {
                remote_upsert.upstreams.clone()
            } else {
                parse_json_vec(&existing_site.upstreams_json).unwrap_or_default()
            },
            safeline_intercept: existing_site
                .safeline_intercept_json
                .as_ref()
                .and_then(|value| serde_json::from_str(value).ok()),
            enabled: if options.enabled {
                remote_upsert.enabled
            } else {
                existing_site.enabled
            },
            tls_enabled: remote_upsert.tls_enabled,
            local_certificate_id: existing_site.local_certificate_id,
            source: existing_site.source.clone(),
            sync_mode: sync_mode.to_string(),
            notes: existing_site.notes.clone(),
            last_synced_at: Some(now),
        }
    } else {
        let mut created = remote_upsert;
        created.hostnames = if options.hostnames {
            created.hostnames
        } else {
            vec![created.primary_hostname.clone()]
        };
        if !created
            .hostnames
            .iter()
            .any(|item| item == &created.primary_hostname)
        {
            created
                .hostnames
                .insert(0, created.primary_hostname.clone());
        }
        if !options.listen_ports {
            created.listen_ports = Vec::new();
        }
        if !options.upstreams {
            created.upstreams = Vec::new();
        }
        if !options.enabled {
            created.enabled = true;
        }
        created.local_certificate_id = None;
        created
    };

    if !merged
        .hostnames
        .iter()
        .any(|item| item == &merged.primary_hostname)
    {
        merged.hostnames.insert(0, merged.primary_hostname.clone());
    }

    merged
}

fn normalized_domain_set(domains: &[String]) -> Vec<String> {
    let mut items = domains
        .iter()
        .map(|item| item.trim().to_ascii_lowercase())
        .filter(|item| !item.is_empty())
        .collect::<Vec<_>>();
    items.sort();
    items.dedup();
    items
}

fn certificate_fingerprint(certificate_pem: &str) -> Option<String> {
    let normalized = certificate_pem.trim();
    if normalized.is_empty() {
        return None;
    }

    let mut hasher = Sha256::new();
    hasher.update(normalized.as_bytes());
    Some(format!("{:x}", hasher.finalize()))
}

fn match_remote_certificate(
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

async fn update_certificate_sync_metadata(
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
    local_certificates: &mut Vec<LocalCertificateEntry>,
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

fn replace_local_site(
    local_sites: &mut Vec<LocalSiteEntry>,
    id: i64,
    upsert: &LocalSiteUpsert,
    now: i64,
) {
    if let Some(item) = local_sites.iter_mut().find(|item| item.id == id) {
        item.name = upsert.name.clone();
        item.primary_hostname = upsert.primary_hostname.clone();
        item.hostnames_json =
            serde_json::to_string(&upsert.hostnames).unwrap_or_else(|_| "[]".to_string());
        item.listen_ports_json =
            serde_json::to_string(&upsert.listen_ports).unwrap_or_else(|_| "[]".to_string());
        item.upstreams_json =
            serde_json::to_string(&upsert.upstreams).unwrap_or_else(|_| "[]".to_string());
        item.safeline_intercept_json = upsert
            .safeline_intercept
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .unwrap_or(None);
        item.enabled = upsert.enabled;
        item.tls_enabled = upsert.tls_enabled;
        item.local_certificate_id = upsert.local_certificate_id;
        item.source = upsert.source.clone();
        item.sync_mode = upsert.sync_mode.clone();
        item.notes = upsert.notes.clone();
        item.last_synced_at = upsert.last_synced_at;
        item.updated_at = now;
    }
}

fn allows_pull(sync_mode: &str) -> bool {
    !matches!(sync_mode.trim(), "local_to_remote" | "push_only")
}

fn allows_push(sync_mode: &str) -> bool {
    !matches!(sync_mode.trim(), "remote_to_local" | "pull_only")
}

fn site_matches_remote(local_site: &LocalSiteEntry, remote_site: &SafeLineSiteSummary) -> bool {
    let local_hosts = parse_json_vec(&local_site.hostnames_json)
        .unwrap_or_else(|_| vec![local_site.primary_hostname.clone()]);
    let mut remote_hosts = remote_site.server_names.clone();

    if !remote_site.domain.trim().is_empty()
        && !remote_hosts.iter().any(|item| item == &remote_site.domain)
    {
        remote_hosts.push(remote_site.domain.clone());
    }

    remote_hosts.iter().any(|remote_host| {
        remote_host == &local_site.primary_hostname
            || local_hosts
                .iter()
                .any(|local_host| local_host == remote_host)
    })
}

fn match_remote_site(
    local_site: &LocalSiteEntry,
    remote_sites: &[SafeLineSiteSummary],
) -> Option<SafeLineSiteSummary> {
    remote_sites
        .iter()
        .find(|remote| site_matches_remote(local_site, remote))
        .cloned()
}

fn find_matching_local_site(
    remote_site: &SafeLineSiteSummary,
    local_sites: &[LocalSiteEntry],
    exclude_local_id: Option<i64>,
) -> Option<LocalSiteEntry> {
    local_sites
        .iter()
        .find(|local_site| {
            if Some(local_site.id) == exclude_local_id {
                return false;
            }
            site_matches_remote(local_site, remote_site)
        })
        .cloned()
}

fn find_matching_remote_site(
    local_site: &LocalSiteEntry,
    remote_sites: &[SafeLineSiteSummary],
    exclude_remote_id: Option<&str>,
) -> Option<SafeLineSiteSummary> {
    remote_sites
        .iter()
        .find(|remote_site| {
            if Some(remote_site.id.as_str()) == exclude_remote_id {
                return false;
            }
            site_matches_remote(local_site, remote_site)
        })
        .cloned()
}

async fn record_site_link_error(
    store: &SqliteStore,
    existing_link: &crate::storage::SiteSyncLinkEntry,
    message: String,
    now: i64,
) -> Result<()> {
    store
        .upsert_site_sync_link(&SiteSyncLinkUpsert {
            local_site_id: existing_link.local_site_id,
            provider: existing_link.provider.clone(),
            remote_site_id: existing_link.remote_site_id.clone(),
            remote_site_name: existing_link.remote_site_name.clone(),
            remote_cert_id: existing_link.remote_cert_id.clone(),
            sync_mode: existing_link.sync_mode.clone(),
            last_local_hash: existing_link.last_local_hash.clone(),
            last_remote_hash: existing_link.last_remote_hash.clone(),
            last_error: Some(message),
            last_synced_at: Some(now),
        })
        .await?;
    Ok(())
}

async fn resolve_remote_certificate_id(
    store: &SqliteStore,
    config: &SafeLineConfig,
    local_site: &LocalSiteEntry,
    local_certificates: &[LocalCertificateEntry],
    result: &mut SafeLineSitesPushResult,
    now: i64,
) -> Result<Option<i64>> {
    let Some(local_certificate_id) = local_site.local_certificate_id else {
        return Ok(None);
    };
    let local_certificate = local_certificates
        .iter()
        .find(|item| item.id == local_certificate_id)
        .ok_or_else(|| {
            anyhow!(
                "本地站点 {} 引用的证书 {} 不存在",
                local_site.id,
                local_certificate_id
            )
        })?;
    let secret = store
        .load_local_certificate_secret(local_certificate_id)
        .await?;
    let remote_id = if let Some(remote_id) = local_certificate.provider_remote_id.as_deref() {
        if let Some(secret) = secret.as_ref() {
            let remote_detail = crate::integrations::safeline::load_certificate(config, remote_id)
                .await
                .ok();
            if let Some(remote_detail) = remote_detail {
                if certificate_material_matches(
                    local_certificate,
                    secret.certificate_pem.as_str(),
                    secret.private_key_pem.as_str(),
                    &remote_detail,
                )? {
                    result.reused_certificates += 1;
                    remote_id.parse::<i64>().ok()
                } else {
                    result.created_certificates += 1;
                    Some(
                        create_remote_certificate(
                            store,
                            config,
                            local_certificate,
                            secret.certificate_pem.as_str(),
                            secret.private_key_pem.as_str(),
                            now,
                        )
                        .await?,
                    )
                }
            } else {
                result.created_certificates += 1;
                Some(
                    create_remote_certificate(
                        store,
                        config,
                        local_certificate,
                        secret.certificate_pem.as_str(),
                        secret.private_key_pem.as_str(),
                        now,
                    )
                    .await?,
                )
            }
        } else {
            result.reused_certificates += 1;
            remote_id.parse::<i64>().ok()
        }
    } else if let Some(secret) = secret.as_ref() {
        result.created_certificates += 1;
        Some(
            create_remote_certificate(
                store,
                config,
                local_certificate,
                secret.certificate_pem.as_str(),
                secret.private_key_pem.as_str(),
                now,
            )
            .await?,
        )
    } else {
        return Err(anyhow!(
            "本地证书 {} 还没有保存 PEM/私钥内容，无法推送到雷池",
            local_certificate_id
        ));
    };

    Ok(remote_id)
}

async fn create_remote_certificate(
    store: &SqliteStore,
    config: &SafeLineConfig,
    local_certificate: &LocalCertificateEntry,
    certificate_pem: &str,
    private_key_pem: &str,
    now: i64,
) -> Result<i64> {
    let domains = parse_json_vec(&local_certificate.domains_json)?;
    let summary = crate::integrations::safeline::create_certificate(
        config,
        &SafeLineCertificateUpsert {
            domains: domains.clone(),
            certificate_pem: certificate_pem.to_string(),
            private_key_pem: private_key_pem.to_string(),
        },
    )
    .await?;

    if !summary.accepted {
        return Err(anyhow!("雷池证书创建失败：{}", summary.message));
    }

    let remote_id = summary
        .remote_id
        .ok_or_else(|| anyhow!("雷池证书创建成功，但未返回证书 ID"))?;
    let remote_id_i64 = remote_id
        .parse::<i64>()
        .map_err(|_| anyhow!("雷池返回的证书 ID 无法解析：{}", remote_id))?;

    let updated = LocalCertificateUpsert {
        name: local_certificate.name.clone(),
        domains: parse_json_vec(&local_certificate.domains_json)?,
        issuer: local_certificate.issuer.clone(),
        valid_from: local_certificate.valid_from,
        valid_to: local_certificate.valid_to,
        source_type: local_certificate.source_type.clone(),
        provider_remote_id: Some(remote_id),
        provider_remote_domains: domains,
        last_remote_fingerprint: certificate_fingerprint(certificate_pem),
        sync_status: "synced".to_string(),
        sync_message: "站点推送时已创建雷池证书。".to_string(),
        auto_sync_enabled: local_certificate.auto_sync_enabled,
        trusted: local_certificate.trusted,
        expired: local_certificate.expired,
        notes: local_certificate.notes.clone(),
        last_synced_at: Some(now),
    };
    store
        .update_local_certificate(local_certificate.id, &updated)
        .await?;

    Ok(remote_id_i64)
}

fn certificate_material_matches(
    local_certificate: &LocalCertificateEntry,
    certificate_pem: &str,
    private_key_pem: &str,
    remote_detail: &SafeLineCertificateDetail,
) -> Result<bool> {
    let local_domains = parse_json_vec(&local_certificate.domains_json)?;
    let local_hash = hash_certificate_material(&local_domains, certificate_pem, private_key_pem);
    let remote_hash = hash_certificate_material(
        &remote_detail.domains,
        remote_detail.certificate_pem.as_deref().unwrap_or_default(),
        remote_detail.private_key_pem.as_deref().unwrap_or_default(),
    );
    Ok(local_hash == remote_hash)
}

fn local_site_to_remote(
    local_site: &LocalSiteEntry,
    remote_certificate_id: Option<i64>,
) -> SafeLineSiteUpsert {
    let hostnames = parse_json_vec(&local_site.hostnames_json)
        .unwrap_or_else(|_| vec![local_site.primary_hostname.clone()]);
    let ports = parse_json_vec(&local_site.listen_ports_json).unwrap_or_default();
    let upstreams = parse_json_vec(&local_site.upstreams_json).unwrap_or_default();

    SafeLineSiteUpsert {
        remote_id: None,
        name: local_site.name.clone(),
        server_names: if hostnames.is_empty() {
            vec![local_site.primary_hostname.clone()]
        } else {
            hostnames
        },
        ports,
        upstreams,
        enabled: local_site.enabled,
        health_check: true,
        cert_id: remote_certificate_id,
        notes: local_site.notes.clone(),
    }
}

async fn update_local_site_sync_metadata(
    store: &SqliteStore,
    local_site: &LocalSiteEntry,
    now: i64,
) -> Result<()> {
    let upsert = LocalSiteUpsert {
        name: local_site.name.clone(),
        primary_hostname: local_site.primary_hostname.clone(),
        hostnames: parse_json_vec(&local_site.hostnames_json)?,
        listen_ports: parse_json_vec(&local_site.listen_ports_json)?,
        upstreams: parse_json_vec(&local_site.upstreams_json)?,
        safeline_intercept: local_site
            .safeline_intercept_json
            .as_deref()
            .map(serde_json::from_str)
            .transpose()?,
        enabled: local_site.enabled,
        tls_enabled: local_site.tls_enabled,
        local_certificate_id: local_site.local_certificate_id,
        source: local_site.source.clone(),
        sync_mode: local_site.sync_mode.clone(),
        notes: local_site.notes.clone(),
        last_synced_at: Some(now),
    };
    store.update_local_site(local_site.id, &upsert).await?;
    Ok(())
}

fn hash_remote_site(site: &SafeLineSiteSummary) -> String {
    let mut hasher = Sha256::new();
    hasher.update(site.id.as_bytes());
    hasher.update([0]);
    hasher.update(site.name.as_bytes());
    hasher.update([0]);
    hasher.update(site.domain.as_bytes());
    hasher.update([0]);
    for item in &site.server_names {
        hasher.update(item.as_bytes());
        hasher.update([0]);
    }
    for item in &site.ports {
        hasher.update(item.as_bytes());
        hasher.update([0]);
    }
    for item in &site.upstreams {
        hasher.update(item.as_bytes());
        hasher.update([0]);
    }
    hasher.update([site.enabled.unwrap_or(false) as u8]);
    hasher.update(site.cert_id.unwrap_or_default().to_le_bytes());
    format!("{:x}", hasher.finalize())
}

fn hash_local_site_upsert(site: &LocalSiteUpsert, remote_cert_id: Option<&str>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(site.name.as_bytes());
    hasher.update([0]);
    hasher.update(site.primary_hostname.as_bytes());
    hasher.update([0]);
    for item in &site.hostnames {
        hasher.update(item.as_bytes());
        hasher.update([0]);
    }
    for item in &site.listen_ports {
        hasher.update(item.as_bytes());
        hasher.update([0]);
    }
    for item in &site.upstreams {
        hasher.update(item.as_bytes());
        hasher.update([0]);
    }
    if let Some(intercept) = site.safeline_intercept.as_ref() {
        hasher.update(
            serde_json::to_string(intercept)
                .unwrap_or_default()
                .as_bytes(),
        );
    }
    hasher.update([0]);
    hasher.update([site.enabled as u8]);
    hasher.update([site.tls_enabled as u8]);
    hasher.update(remote_cert_id.unwrap_or_default().as_bytes());
    format!("{:x}", hasher.finalize())
}

fn hash_local_site_entry(site: &LocalSiteEntry, remote_cert_id: Option<&str>) -> Result<String> {
    Ok(hash_local_site_upsert(
        &LocalSiteUpsert {
            name: site.name.clone(),
            primary_hostname: site.primary_hostname.clone(),
            hostnames: parse_json_vec(&site.hostnames_json)?,
            listen_ports: parse_json_vec(&site.listen_ports_json)?,
            upstreams: parse_json_vec(&site.upstreams_json)?,
            safeline_intercept: site
                .safeline_intercept_json
                .as_deref()
                .map(serde_json::from_str)
                .transpose()?,
            enabled: site.enabled,
            tls_enabled: site.tls_enabled,
            local_certificate_id: site.local_certificate_id,
            source: site.source.clone(),
            sync_mode: site.sync_mode.clone(),
            notes: site.notes.clone(),
            last_synced_at: site.last_synced_at,
        },
        remote_cert_id,
    ))
}

fn hash_certificate_material(
    domains: &[String],
    certificate_pem: &str,
    private_key_pem: &str,
) -> String {
    let mut hasher = Sha256::new();
    for item in domains {
        hasher.update(item.as_bytes());
        hasher.update([0]);
    }
    hasher.update(normalize_pem(certificate_pem).as_bytes());
    hasher.update([0]);
    hasher.update(normalize_pem(private_key_pem).as_bytes());
    format!("{:x}", hasher.finalize())
}

fn normalize_pem(value: &str) -> String {
    value
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

fn parse_json_vec(value: &str) -> Result<Vec<String>> {
    Ok(serde_json::from_str::<Vec<String>>(value)?)
}

fn unix_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
