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
    let mut result = SafeLineSitesPullResult::default();
    let mut local_sites = store.list_local_sites().await?;
    let existing_links = store.list_site_sync_links().await?;

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

        let site_upsert = local_site_upsert_from_remote(remote_site, None, sync_mode, now);
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
                safeline_intercept_json: site_upsert
                    .safeline_intercept
                    .as_ref()
                    .map(serde_json::to_string)
                    .transpose()?,
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

pub async fn pull_certificates(
    store: &SqliteStore,
    config: &SafeLineConfig,
) -> Result<SafeLineCertificatesPullResult> {
    ensure_enabled(config)?;

    let now = unix_timestamp();
    let remote_certificates = crate::integrations::safeline::list_certificates(config).await?;
    let mut local_certificates = store.list_local_certificates().await?;
    let mut result = SafeLineCertificatesPullResult::default();

    for certificate in &remote_certificates {
        let detail = crate::integrations::safeline::load_certificate(config, &certificate.id)
            .await
            .ok();
        let sync_state =
            sync_remote_certificate(store, &mut local_certificates, certificate, detail, now)
                .await?;
        if sync_state.inserted {
            result.imported_certificates += 1;
        } else {
            result.updated_certificates += 1;
        }
    }

    store
        .upsert_safeline_sync_state(
            "certificates_pull",
            Some(now),
            result.imported_certificates + result.updated_certificates,
            result.skipped_certificates,
        )
        .await?;

    Ok(result)
}

pub async fn pull_certificate(
    store: &SqliteStore,
    config: &SafeLineConfig,
    remote_cert_id: &str,
) -> Result<i64> {
    ensure_enabled(config)?;

    let remote_cert_id = remote_cert_id.trim();
    if remote_cert_id.is_empty() {
        bail!("remote_cert_id 不能为空");
    }

    let now = unix_timestamp();
    let remote_certificates = crate::integrations::safeline::list_certificates(config).await?;
    let certificate = remote_certificates
        .iter()
        .find(|item| item.id == remote_cert_id)
        .ok_or_else(|| anyhow!("雷池证书 '{}' 不存在或当前账号不可见", remote_cert_id))?;
    let detail = crate::integrations::safeline::load_certificate(config, remote_cert_id)
        .await
        .ok();
    let mut local_certificates = store.list_local_certificates().await?;
    let sync_state =
        sync_remote_certificate(store, &mut local_certificates, certificate, detail, now).await?;
    store
        .upsert_safeline_sync_state("certificates_pull", Some(now), 1, 0)
        .await?;
    Ok(sync_state.local_id)
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

pub async fn pull_site(
    store: &SqliteStore,
    config: &SafeLineConfig,
    remote_site_id: &str,
    options: SafeLineSitePullOptions,
) -> Result<SafeLineSingleSitePullResult> {
    ensure_enabled(config)?;

    let remote_site_id = remote_site_id.trim();
    if remote_site_id.is_empty() {
        bail!("remote_site_id 不能为空");
    }

    let now = unix_timestamp();
    let remote_sites = crate::integrations::safeline::list_sites(config).await?;
    let remote_site = remote_sites
        .into_iter()
        .find(|item| item.id == remote_site_id)
        .ok_or_else(|| anyhow!("雷池站点 '{}' 不存在或当前账号不可见", remote_site_id))?;

    let existing_links = store.list_site_sync_links().await?;
    let existing_link = existing_links
        .iter()
        .find(|item| item.provider == "safeline" && item.remote_site_id == remote_site.id)
        .cloned();
    let sync_mode = existing_link
        .as_ref()
        .map(|item| item.sync_mode.as_str())
        .unwrap_or("remote_to_local");

    if !allows_pull(sync_mode) {
        bail!("站点 '{}' 当前链路配置不允许从雷池回流", remote_site.id);
    }

    let mut local_sites = store.list_local_sites().await?;
    let linked_local_id = existing_link.as_ref().map(|item| item.local_site_id);

    if let Some(conflict) = find_matching_local_site(&remote_site, &local_sites, linked_local_id) {
        bail!(
            "发现疑似重复的本地站点 #{}（{}），为避免覆盖现有配置，请先确认链路后再同步。",
            conflict.id,
            conflict.primary_hostname
        );
    }

    let existing_local_site = existing_link.as_ref().and_then(|link| {
        local_sites
            .iter()
            .find(|item| item.id == link.local_site_id)
            .cloned()
    });
    let site_upsert = merge_local_site_upsert_from_remote(
        &remote_site,
        None,
        sync_mode,
        now,
        existing_local_site.as_ref(),
        options,
    );

    let (local_site_id, action) = if let Some(existing_site) = existing_local_site {
        store
            .update_local_site(existing_site.id, &site_upsert)
            .await?;
        replace_local_site(&mut local_sites, existing_site.id, &site_upsert, now);
        (existing_site.id, SingleSiteSyncAction::Updated)
    } else {
        let local_site_id = store.insert_local_site(&site_upsert).await?;
        local_sites.push(LocalSiteEntry {
            id: local_site_id,
            name: site_upsert.name.clone(),
            primary_hostname: site_upsert.primary_hostname.clone(),
            hostnames_json: serde_json::to_string(&site_upsert.hostnames)?,
            listen_ports_json: serde_json::to_string(&site_upsert.listen_ports)?,
            upstreams_json: serde_json::to_string(&site_upsert.upstreams)?,
            safeline_intercept_json: site_upsert
                .safeline_intercept
                .as_ref()
                .map(serde_json::to_string)
                .transpose()?,
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
        (local_site_id, SingleSiteSyncAction::Created)
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
            last_remote_hash: Some(hash_remote_site(&remote_site)),
            last_error: None,
            last_synced_at: Some(now),
        })
        .await?;

    store
        .upsert_safeline_sync_state("sites_pull", Some(now), 1, 0)
        .await?;

    Ok(SafeLineSingleSitePullResult {
        action,
        local_site_id,
        remote_site_id: remote_site.id,
    })
}

pub async fn push_site(
    store: &SqliteStore,
    config: &SafeLineConfig,
    local_site_id: i64,
) -> Result<SafeLineSingleSitePushResult> {
    ensure_enabled(config)?;

    if local_site_id <= 0 {
        bail!("local_site_id 必须大于 0");
    }

    let now = unix_timestamp();
    let local_sites = store.list_local_sites().await?;
    let local_site = local_sites
        .iter()
        .find(|item| item.id == local_site_id)
        .cloned()
        .ok_or_else(|| anyhow!("本地站点 '{}' 不存在", local_site_id))?;
    let local_certificates = store.list_local_certificates().await?;
    let existing_links = store.list_site_sync_links().await?;
    let remote_sites = crate::integrations::safeline::list_sites(config).await?;
    let existing_link = existing_links
        .iter()
        .find(|item| item.provider == "safeline" && item.local_site_id == local_site.id)
        .cloned();
    let sync_mode = existing_link
        .as_ref()
        .map(|item| item.sync_mode.as_str())
        .unwrap_or(local_site.sync_mode.as_str());

    if !allows_push(sync_mode) {
        bail!("本地站点 #{} 当前链路配置不允许推送到雷池", local_site.id);
    }

    let linked_remote_site = existing_link.as_ref().and_then(|link| {
        remote_sites
            .iter()
            .find(|item| item.id == link.remote_site_id)
            .cloned()
    });

    if existing_link.is_none() {
        if let Some(conflict) = find_matching_remote_site(&local_site, &remote_sites, None) {
            bail!(
                "发现疑似重复的雷池站点 '{}'（{}），为避免覆盖现有配置，请先建立明确链路后再推送。",
                conflict.id,
                conflict.domain
            );
        }
    } else if linked_remote_site.is_none() {
        if let Some(conflict) = find_matching_remote_site(&local_site, &remote_sites, None) {
            bail!(
                "原有链路指向的雷池站点已不存在，但检测到相似站点 '{}'（{}），为避免误覆盖请先核对后再处理。",
                conflict.id,
                conflict.domain
            );
        }
    }

    let mut push_result = SafeLineSitesPushResult::default();
    let remote_certificate_id = match resolve_remote_certificate_id(
        store,
        config,
        &local_site,
        &local_certificates,
        &mut push_result,
        now,
    )
    .await
    {
        Ok(value) => value,
        Err(err) => {
            if let Some(existing_link) = existing_link.as_ref() {
                record_site_link_error(store, existing_link, err.to_string(), now).await?;
            }
            return Err(err);
        }
    };

    let mut site_upsert = local_site_to_remote(&local_site, remote_certificate_id);
    site_upsert.remote_id = linked_remote_site.as_ref().map(|item| item.id.clone());

    let site_summary = crate::integrations::safeline::upsert_site(config, &site_upsert).await?;
    if !site_summary.accepted {
        if let Some(existing_link) = existing_link.as_ref() {
            record_site_link_error(store, existing_link, site_summary.message.clone(), now).await?;
        }
        bail!("{}", site_summary.message);
    }

    let remote_site_id = site_summary
        .remote_id
        .clone()
        .or_else(|| linked_remote_site.as_ref().map(|item| item.id.clone()))
        .ok_or_else(|| anyhow!("雷池站点写入成功，但响应里未返回站点 ID"))?;
    let remote_site_name = linked_remote_site
        .as_ref()
        .map(|item| item.name.clone())
        .unwrap_or_else(|| local_site.name.clone());
    let local_hash = hash_local_site_entry(
        &local_site,
        remote_certificate_id
            .as_ref()
            .map(|id| id.to_string())
            .as_deref(),
    )?;

    store
        .upsert_site_sync_link(&SiteSyncLinkUpsert {
            local_site_id: local_site.id,
            provider: "safeline".to_string(),
            remote_site_id: remote_site_id.clone(),
            remote_site_name,
            remote_cert_id: remote_certificate_id.map(|id| id.to_string()),
            sync_mode: sync_mode.to_string(),
            last_local_hash: Some(local_hash.clone()),
            last_remote_hash: Some(local_hash),
            last_error: None,
            last_synced_at: Some(now),
        })
        .await?;

    update_local_site_sync_metadata(store, &local_site, now).await?;
    store
        .upsert_safeline_sync_state("sites_push", Some(now), 1, 0)
        .await?;

    Ok(SafeLineSingleSitePushResult {
        action: if linked_remote_site.is_some() {
            SingleSiteSyncAction::Updated
        } else {
            SingleSiteSyncAction::Created
        },
        local_site_id: local_site.id,
        remote_site_id,
    })
}

pub async fn push_certificate(
    store: &SqliteStore,
    config: &SafeLineConfig,
    local_certificate_id: i64,
) -> Result<String> {
    ensure_enabled(config)?;

    if local_certificate_id <= 0 {
        bail!("local_certificate_id 必须大于 0");
    }

    let now = unix_timestamp();
    let local_certificate = store
        .load_local_certificate(local_certificate_id)
        .await?
        .ok_or_else(|| anyhow!("本地证书 '{}' 不存在", local_certificate_id))?;
    let secret = store
        .load_local_certificate_secret(local_certificate_id)
        .await?
        .ok_or_else(|| {
            anyhow!(
                "本地证书 #{} 缺少证书内容，无法推送到雷池",
                local_certificate_id
            )
        })?;

    if secret.certificate_pem.trim().is_empty() || secret.private_key_pem.trim().is_empty() {
        update_certificate_sync_metadata(
            store,
            &local_certificate,
            CertificateSyncMetadataUpdate {
                provider_remote_id: local_certificate.provider_remote_id.clone(),
                provider_remote_domains: parse_json_vec(
                    &local_certificate.provider_remote_domains_json,
                )
                .unwrap_or_default(),
                last_remote_fingerprint: local_certificate.last_remote_fingerprint.clone(),
                sync_status: "blocked".to_string(),
                sync_message: "本地证书缺少完整私钥，无法推送到雷池".to_string(),
                last_synced_at: local_certificate.last_synced_at,
            },
        )
        .await?;
        bail!(
            "本地证书 #{} 缺少完整私钥，无法推送到雷池",
            local_certificate_id
        );
    }

    let local_domains = parse_json_vec(&local_certificate.domains_json)?;
    let remote_certificates = crate::integrations::safeline::list_certificates(config).await?;
    let match_result =
        match_remote_certificate(&local_certificate, &local_domains, &remote_certificates)?;

    let payload = SafeLineCertificateUpsert {
        domains: local_domains.clone(),
        certificate_pem: secret.certificate_pem.clone(),
        private_key_pem: secret.private_key_pem.clone(),
    };

    let summary = if let Some(remote_id) = match_result.remote_id.as_deref() {
        crate::integrations::safeline::update_certificate(config, remote_id, &payload).await?
    } else {
        crate::integrations::safeline::create_certificate(config, &payload).await?
    };

    if !summary.accepted {
        update_certificate_sync_metadata(
            store,
            &local_certificate,
            CertificateSyncMetadataUpdate {
                provider_remote_id: local_certificate.provider_remote_id.clone(),
                provider_remote_domains: match_result.remote_domains,
                last_remote_fingerprint: local_certificate.last_remote_fingerprint.clone(),
                sync_status: "error".to_string(),
                sync_message: summary.message.clone(),
                last_synced_at: local_certificate.last_synced_at,
            },
        )
        .await?;
        bail!("{}", summary.message);
    }

    let remote_id = summary
        .remote_id
        .clone()
        .or_else(|| match_result.remote_id.clone())
        .ok_or_else(|| anyhow!("雷池证书写入成功，但未返回远端证书 ID"))?;

    update_certificate_sync_metadata(
        store,
        &local_certificate,
        CertificateSyncMetadataUpdate {
            provider_remote_id: Some(remote_id.clone()),
            provider_remote_domains: local_domains,
            last_remote_fingerprint: certificate_fingerprint(&secret.certificate_pem),
            sync_status: "synced".to_string(),
            sync_message: match_result.success_message(&remote_id),
            last_synced_at: Some(now),
        },
    )
    .await?;

    store
        .upsert_safeline_sync_state("certificates_push", Some(now), 1, 0)
        .await?;

    Ok(remote_id)
}

pub async fn preview_certificate_match(
    store: &SqliteStore,
    config: &SafeLineConfig,
    local_certificate_id: i64,
) -> Result<CertificateMatchPreview> {
    ensure_enabled(config)?;

    if local_certificate_id <= 0 {
        bail!("local_certificate_id 必须大于 0");
    }

    let local_certificate = store
        .load_local_certificate(local_certificate_id)
        .await?
        .ok_or_else(|| anyhow!("本地证书 '{}' 不存在", local_certificate_id))?;
    let local_domains = parse_json_vec(&local_certificate.domains_json)?;
    let normalized_local_domains = normalized_domain_set(&local_domains);
    let remote_certificates = crate::integrations::safeline::list_certificates(config).await?;

    if let Some(remote_id) = local_certificate.provider_remote_id.as_deref() {
        if let Some(remote) = remote_certificates.iter().find(|item| item.id == remote_id) {
            let normalized_remote_domains = normalized_domain_set(&remote.domains);
            if normalized_remote_domains == normalized_local_domains {
                return Ok(CertificateMatchPreview {
                    status: "ok".to_string(),
                    strategy: "remote_id".to_string(),
                    local_certificate_id,
                    local_domains,
                    linked_remote_id: local_certificate.provider_remote_id.clone(),
                    matched_remote_id: Some(remote.id.clone()),
                    message: format!("将按已绑定的雷池证书 ID {} 直接更新。", remote.id),
                    candidates: vec![remote.clone()],
                });
            }

            return Ok(CertificateMatchPreview {
                status: "conflict".to_string(),
                strategy: "drifted".to_string(),
                local_certificate_id,
                local_domains,
                linked_remote_id: local_certificate.provider_remote_id.clone(),
                matched_remote_id: Some(remote.id.clone()),
                message: format!(
                    "已绑定的雷池证书 {} 仍存在，但域名集合已漂移。本地：{}；远端：{}。",
                    remote.id,
                    normalized_local_domains.join(", "),
                    normalized_remote_domains.join(", ")
                ),
                candidates: vec![remote.clone()],
            });
        }
    }

    let domain_matches = remote_certificates
        .iter()
        .filter(|item| normalized_domain_set(&item.domains) == normalized_local_domains)
        .cloned()
        .collect::<Vec<_>>();

    if domain_matches.len() == 1 {
        let remote = domain_matches[0].clone();
        return Ok(CertificateMatchPreview {
            status: "ok".to_string(),
            strategy: "domains".to_string(),
            local_certificate_id,
            local_domains,
            linked_remote_id: local_certificate.provider_remote_id.clone(),
            matched_remote_id: Some(remote.id.clone()),
            message: format!(
                "未命中已绑定 ID，将按域名集合匹配并更新雷池证书 {}。",
                remote.id
            ),
            candidates: vec![remote],
        });
    }

    if domain_matches.len() > 1 {
        return Ok(CertificateMatchPreview {
            status: "conflict".to_string(),
            strategy: "domains".to_string(),
            local_certificate_id,
            local_domains,
            linked_remote_id: local_certificate.provider_remote_id.clone(),
            matched_remote_id: None,
            message: "雷池中存在多张域名集合相同的证书，当前不会自动覆盖，请先人工确认目标。"
                .to_string(),
            candidates: domain_matches,
        });
    }

    Ok(CertificateMatchPreview {
        status: "create".to_string(),
        strategy: "create".to_string(),
        local_certificate_id,
        local_domains,
        linked_remote_id: local_certificate.provider_remote_id.clone(),
        matched_remote_id: None,
        message: "未找到可复用的雷池证书，推送时将创建新证书。".to_string(),
        candidates: Vec::new(),
    })
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
