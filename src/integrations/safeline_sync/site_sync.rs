use super::*;
use sha2::{Digest, Sha256};

pub(super) fn allows_push(sync_mode: &str) -> bool {
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

pub(super) fn match_remote_site(
    local_site: &LocalSiteEntry,
    remote_sites: &[SafeLineSiteSummary],
) -> Option<SafeLineSiteSummary> {
    remote_sites
        .iter()
        .find(|remote| site_matches_remote(local_site, remote))
        .cloned()
}

pub(super) fn find_matching_remote_site(
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

pub(super) async fn record_site_link_error(
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

pub(super) async fn resolve_remote_certificate_id(
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

pub(super) fn local_site_to_remote(
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

pub(super) async fn update_local_site_sync_metadata(
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

pub(super) fn hash_remote_site(site: &SafeLineSiteSummary) -> String {
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

pub(super) fn hash_local_site_entry(
    site: &LocalSiteEntry,
    remote_cert_id: Option<&str>,
) -> Result<String> {
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
