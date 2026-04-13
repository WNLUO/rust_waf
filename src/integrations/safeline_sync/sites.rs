use super::*;

fn cached_site_from_remote(
    value: &crate::integrations::safeline::SafeLineSiteSummary,
) -> Result<crate::storage::SafeLineCachedSiteUpsert> {
    Ok(crate::storage::SafeLineCachedSiteUpsert {
        remote_site_id: value.id.clone(),
        name: value.name.clone(),
        domain: value.domain.clone(),
        status: value.status.clone(),
        enabled: value.enabled,
        server_names: value.server_names.clone(),
        ports: value.ports.clone(),
        ssl_ports: value.ssl_ports.clone(),
        upstreams: value.upstreams.clone(),
        ssl_enabled: value.ssl_enabled,
        cert_id: value.cert_id,
        cert_type: value.cert_type,
        cert_filename: value.cert_filename.clone(),
        key_filename: value.key_filename.clone(),
        health_check: value.health_check,
        raw_json: serde_json::to_string(&value.raw)?,
    })
}

pub async fn pull_sites(
    store: &SqliteStore,
    config: &SafeLineConfig,
) -> Result<SafeLineSitesPullResult> {
    ensure_enabled(config)?;

    let now = unix_timestamp();
    let remote_sites = crate::integrations::safeline::list_sites(config).await?;
    let existing_cache = store.list_safeline_cached_sites().await?;
    if remote_sites.is_empty() && !existing_cache.is_empty() {
        store
            .upsert_safeline_sync_state("sites_pull", Some(now), 0, existing_cache.len())
            .await?;
        return Ok(SafeLineSitesPullResult {
            skipped_sites: existing_cache.len(),
            ..SafeLineSitesPullResult::default()
        });
    }
    let cached_sites = remote_sites
        .iter()
        .map(cached_site_from_remote)
        .collect::<Result<Vec<_>, _>>()?;

    let mut result = SafeLineSitesPullResult::default();
    for remote_site in &remote_sites {
        if existing_cache
            .iter()
            .any(|item| item.remote_site_id == remote_site.id)
        {
            result.updated_sites += 1;
        } else {
            result.imported_sites += 1;
        }
    }

    store.replace_safeline_cached_sites(&cached_sites).await?;
    store
        .upsert_safeline_sync_state(
            "sites_pull",
            Some(now),
            result.imported_sites + result.updated_sites,
            0,
        )
        .await?;

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

pub async fn pull_site(
    store: &SqliteStore,
    config: &SafeLineConfig,
    remote_site_id: &str,
    _options: SafeLineSitePullOptions,
) -> Result<SafeLineSingleSitePullResult> {
    ensure_enabled(config)?;

    let remote_site_id = remote_site_id.trim();
    if remote_site_id.is_empty() {
        bail!("remote_site_id 不能为空");
    }

    let now = unix_timestamp();
    let remote_sites = crate::integrations::safeline::list_sites(config).await?;
    let existing_cache = store.list_safeline_cached_sites().await?;
    let remote_site = remote_sites
        .iter()
        .find(|item| item.id == remote_site_id)
        .ok_or_else(|| anyhow!("雷池站点 '{}' 不存在或当前账号不可见", remote_site_id))?;
    let action = if existing_cache
        .iter()
        .any(|item| item.remote_site_id == remote_site.id)
    {
        SingleSiteSyncAction::Updated
    } else {
        SingleSiteSyncAction::Created
    };

    let cached_sites = remote_sites
        .iter()
        .map(cached_site_from_remote)
        .collect::<Result<Vec<_>, _>>()?;
    let existing_cache = store.list_safeline_cached_sites().await?;
    if cached_sites.is_empty() && !existing_cache.is_empty() {
        store
            .upsert_safeline_sync_state("sites_pull", Some(now), 0, existing_cache.len())
            .await?;
    } else {
        store.replace_safeline_cached_sites(&cached_sites).await?;

        store
            .upsert_safeline_sync_state("sites_pull", Some(now), 1, 0)
            .await?;
    }

    Ok(SafeLineSingleSitePullResult {
        action,
        remote_site_id: remote_site.id.clone(),
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
