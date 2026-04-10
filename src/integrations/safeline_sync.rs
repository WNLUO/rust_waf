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
use std::collections::HashSet;

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

pub async fn sync_events(
    store: &SqliteStore,
    config: &SafeLineConfig,
) -> Result<SafeLineImportResult> {
    ensure_enabled(config)?;

    let mappings = store.list_safeline_site_mappings().await?;
    let events = crate::integrations::safeline::list_security_events(config).await?;
    let records = events
        .into_iter()
        .map(|event| apply_safeline_mapping(event, &mappings))
        .collect::<Vec<_>>();

    store.import_safeline_security_events(&records).await
}

pub async fn pull_sites(
    store: &SqliteStore,
    config: &SafeLineConfig,
) -> Result<SafeLineSitesPullResult> {
    ensure_enabled(config)?;

    let now = unix_timestamp();
    let remote_sites = crate::integrations::safeline::list_sites(config).await?;
    let remote_certificates = crate::integrations::safeline::list_certificates(config).await?;
    let referenced_certificate_ids = remote_sites
        .iter()
        .filter_map(|item| item.cert_id.map(|id| id.to_string()))
        .collect::<HashSet<_>>();

    let mut result = SafeLineSitesPullResult::default();
    let mut local_certificates = store.list_local_certificates().await?;
    let mut local_sites = store.list_local_sites().await?;
    let existing_links = store.list_site_sync_links().await?;

    for certificate in &remote_certificates {
        let local_id = sync_remote_certificate(
            store,
            &mut local_certificates,
            certificate,
            if referenced_certificate_ids.contains(&certificate.id) {
                crate::integrations::safeline::load_certificate(config, &certificate.id)
                    .await
                    .ok()
            } else {
                None
            },
            now,
        )
        .await?;

        if local_id.inserted {
            result.imported_certificates += 1;
        } else {
            result.updated_certificates += 1;
        }
    }

    for remote_site in &remote_sites {
        let existing_link = existing_links
            .iter()
            .find(|item| item.provider == "safeline" && item.remote_site_id == remote_site.id);
        let sync_mode = existing_link
            .map(|item| item.sync_mode.as_str())
            .unwrap_or("remote_to_local");
        if !allows_pull(sync_mode) {
            result.skipped_sites += 1;
            continue;
        }

        let local_certificate_id = remote_site.cert_id.and_then(|cert_id| {
            local_certificates
                .iter()
                .find(|item| {
                    item.provider_remote_id.as_deref() == Some(cert_id.to_string().as_str())
                })
                .map(|item| item.id)
        });

        let site_upsert =
            local_site_upsert_from_remote(remote_site, local_certificate_id, sync_mode, now);
        let existing_site = existing_link.and_then(|link| {
            local_sites
                .iter()
                .find(|item| item.id == link.local_site_id)
                .cloned()
        });

        let local_site_id = if let Some(existing_site) = existing_site {
            store
                .update_local_site(existing_site.id, &site_upsert)
                .await?;
            replace_local_site(&mut local_sites, existing_site.id, &site_upsert, now);
            result.updated_sites += 1;
            existing_site.id
        } else {
            let local_site_id = store.insert_local_site(&site_upsert).await?;
            local_sites.push(LocalSiteEntry {
                id: local_site_id,
                name: site_upsert.name.clone(),
                primary_hostname: site_upsert.primary_hostname.clone(),
                hostnames_json: serde_json::to_string(&site_upsert.hostnames)?,
                listen_ports_json: serde_json::to_string(&site_upsert.listen_ports)?,
                upstreams_json: serde_json::to_string(&site_upsert.upstreams)?,
                enabled: site_upsert.enabled,
                tls_enabled: site_upsert.tls_enabled,
                local_certificate_id: site_upsert.local_certificate_id,
                source: site_upsert.source.clone(),
                sync_mode: site_upsert.sync_mode.clone(),
                notes: site_upsert.notes.clone(),
                last_synced_at: site_upsert.last_synced_at,
                created_at: now,
                updated_at: now,
            });
            result.imported_sites += 1;
            local_site_id
        };

        store
            .upsert_site_sync_link(&SiteSyncLinkUpsert {
                local_site_id,
                provider: "safeline".to_string(),
                remote_site_id: remote_site.id.clone(),
                remote_site_name: remote_site.name.clone(),
                remote_cert_id: remote_site.cert_id.map(|id| id.to_string()),
                sync_mode: sync_mode.to_string(),
                last_local_hash: Some(hash_local_site_upsert(
                    &site_upsert,
                    remote_site.cert_id.map(|id| id.to_string()).as_deref(),
                )),
                last_remote_hash: Some(hash_remote_site(remote_site)),
                last_error: None,
                last_synced_at: Some(now),
            })
            .await?;
        result.linked_sites += 1;
    }

    if result.updated_sites > 0 || result.imported_sites > 0 {
        store
            .upsert_safeline_sync_state(
                "sites_pull",
                Some(now),
                result.imported_sites + result.updated_sites,
                result.skipped_sites,
            )
            .await?;
    }

    Ok(result)
}

pub async fn push_sites(
    store: &SqliteStore,
    config: &SafeLineConfig,
) -> Result<SafeLineSitesPushResult> {
    ensure_enabled(config)?;

    let now = unix_timestamp();
    let local_sites = store.list_local_sites().await?;
    let local_certificates = store.list_local_certificates().await?;
    let existing_links = store.list_site_sync_links().await?;
    let remote_sites = crate::integrations::safeline::list_sites(config).await?;

    let mut result = SafeLineSitesPushResult::default();

    for local_site in &local_sites {
        let existing_link = existing_links
            .iter()
            .find(|item| item.provider == "safeline" && item.local_site_id == local_site.id);
        let sync_mode = existing_link
            .map(|item| item.sync_mode.as_str())
            .unwrap_or(local_site.sync_mode.as_str());

        if !allows_push(sync_mode) {
            result.skipped_sites += 1;
            continue;
        }

        let remote_site_guess = existing_link
            .and_then(|item| {
                remote_sites
                    .iter()
                    .find(|site| site.id == item.remote_site_id)
                    .cloned()
            })
            .or_else(|| match_remote_site(local_site, &remote_sites));

        let remote_certificate = resolve_remote_certificate_id(
            store,
            config,
            local_site,
            &local_certificates,
            &mut result,
            now,
        )
        .await;

        let remote_certificate_id = match remote_certificate {
            Ok(value) => value,
            Err(err) => {
                result.failed_sites += 1;
                store
                    .upsert_site_sync_link(&SiteSyncLinkUpsert {
                        local_site_id: local_site.id,
                        provider: "safeline".to_string(),
                        remote_site_id: existing_link
                            .map(|item| item.remote_site_id.clone())
                            .or_else(|| remote_site_guess.as_ref().map(|item| item.id.clone()))
                            .unwrap_or_default(),
                        remote_site_name: existing_link
                            .map(|item| item.remote_site_name.clone())
                            .or_else(|| remote_site_guess.as_ref().map(|item| item.name.clone()))
                            .unwrap_or_else(|| local_site.name.clone()),
                        remote_cert_id: existing_link.and_then(|item| item.remote_cert_id.clone()),
                        sync_mode: sync_mode.to_string(),
                        last_local_hash: existing_link
                            .and_then(|item| item.last_local_hash.clone()),
                        last_remote_hash: existing_link
                            .and_then(|item| item.last_remote_hash.clone()),
                        last_error: Some(err.to_string()),
                        last_synced_at: Some(now),
                    })
                    .await?;
                continue;
            }
        };

        let mut site_upsert = local_site_to_remote(local_site, remote_certificate_id);
        site_upsert.remote_id = existing_link
            .map(|item| item.remote_site_id.clone())
            .or_else(|| remote_site_guess.as_ref().map(|item| item.id.clone()));
        let site_summary = crate::integrations::safeline::upsert_site(config, &site_upsert).await?;

        if site_summary.accepted {
            let remote_site_id = site_summary
                .remote_id
                .clone()
                .or_else(|| remote_site_guess.as_ref().map(|item| item.id.clone()))
                .or_else(|| existing_link.map(|item| item.remote_site_id.clone()))
                .ok_or_else(|| anyhow!("雷池站点写入成功，但响应里未返回站点 ID"))?;
            let remote_site_name = remote_site_guess
                .as_ref()
                .map(|item| item.name.clone())
                .unwrap_or_else(|| local_site.name.clone());
            let local_hash = hash_local_site_entry(
                local_site,
                remote_certificate_id
                    .as_ref()
                    .map(|id| id.to_string())
                    .as_deref(),
            )?;
            let remote_hash = remote_site_guess
                .as_ref()
                .map(hash_remote_site)
                .unwrap_or_else(|| local_hash.clone());

            store
                .upsert_site_sync_link(&SiteSyncLinkUpsert {
                    local_site_id: local_site.id,
                    provider: "safeline".to_string(),
                    remote_site_id: remote_site_id.clone(),
                    remote_site_name,
                    remote_cert_id: remote_certificate_id.map(|id| id.to_string()),
                    sync_mode: sync_mode.to_string(),
                    last_local_hash: Some(local_hash),
                    last_remote_hash: Some(remote_hash),
                    last_error: None,
                    last_synced_at: Some(now),
                })
                .await?;

            update_local_site_sync_metadata(store, local_site, now).await?;

            if existing_link.is_some() || remote_site_guess.is_some() {
                result.updated_sites += 1;
            } else {
                result.created_sites += 1;
            }
        } else {
            result.failed_sites += 1;
            store
                .upsert_site_sync_link(&SiteSyncLinkUpsert {
                    local_site_id: local_site.id,
                    provider: "safeline".to_string(),
                    remote_site_id: existing_link
                        .map(|item| item.remote_site_id.clone())
                        .or_else(|| remote_site_guess.as_ref().map(|item| item.id.clone()))
                        .unwrap_or_default(),
                    remote_site_name: existing_link
                        .map(|item| item.remote_site_name.clone())
                        .or_else(|| remote_site_guess.as_ref().map(|item| item.name.clone()))
                        .unwrap_or_else(|| local_site.name.clone()),
                    remote_cert_id: remote_certificate_id.map(|id| id.to_string()),
                    sync_mode: sync_mode.to_string(),
                    last_local_hash: existing_link.and_then(|item| item.last_local_hash.clone()),
                    last_remote_hash: existing_link.and_then(|item| item.last_remote_hash.clone()),
                    last_error: Some(site_summary.message),
                    last_synced_at: Some(now),
                })
                .await?;
        }
    }

    store
        .upsert_safeline_sync_state(
            "sites_push",
            Some(now),
            result.created_sites + result.updated_sites,
            result.skipped_sites + result.failed_sites,
        )
        .await?;

    Ok(result)
}

pub async fn push_blocked_ips(
    store: &SqliteStore,
    config: &SafeLineConfig,
) -> Result<SafeLineBlocklistSyncResult> {
    ensure_enabled(config)?;

    let blocked = store
        .list_blocked_ips(&BlockedIpQuery {
            limit: 200,
            active_only: true,
            ..BlockedIpQuery::default()
        })
        .await?;

    let mut accepted = Vec::new();
    let mut failed = 0usize;

    for record in &blocked.items {
        let result = crate::integrations::safeline::push_blocked_ip(config, record).await?;
        if result.accepted {
            accepted.push(record.clone());
        } else {
            failed += 1;
        }
    }

    store
        .import_safeline_blocked_ips_sync_result(&accepted, failed)
        .await
}

pub async fn pull_blocked_ips(
    store: &SqliteStore,
    config: &SafeLineConfig,
) -> Result<SafeLineBlocklistPullResult> {
    ensure_enabled(config)?;

    let records = crate::integrations::safeline::list_blocked_ips(config)
        .await?
        .into_iter()
        .map(BlockedIpRecord::from)
        .collect::<Vec<_>>();

    store.import_safeline_blocked_ips_pull(&records).await
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
        if let (Some(certificate_pem), Some(private_key_pem)) = (
            detail.certificate_pem.as_deref(),
            detail.private_key_pem.as_deref(),
        ) {
            if !certificate_pem.trim().is_empty() && !private_key_pem.trim().is_empty() {
                store
                    .upsert_local_certificate_secret(local_id, certificate_pem, private_key_pem)
                    .await?;
            }
        }
    }

    Ok(SyncInsertState { inserted })
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

fn match_remote_site(
    local_site: &LocalSiteEntry,
    remote_sites: &[SafeLineSiteSummary],
) -> Option<SafeLineSiteSummary> {
    let local_hosts = parse_json_vec(&local_site.hostnames_json).ok()?;

    remote_sites
        .iter()
        .find(|remote| {
            remote.domain == local_site.primary_hostname
                || remote
                    .server_names
                    .iter()
                    .any(|name| local_hosts.iter().any(|item| item == name))
        })
        .cloned()
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
            domains,
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
