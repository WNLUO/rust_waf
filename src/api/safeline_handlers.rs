use super::*;

pub(super) async fn test_safeline_handler(
    ExtractJson(payload): ExtractJson<SafeLineTestRequest>,
) -> ApiResult<Json<SafeLineTestResponse>> {
    let result = crate::integrations::safeline::probe(&payload.into_config())
        .await
        .map_err(|err| ApiError::bad_request(err.to_string()))?;

    Ok(Json(SafeLineTestResponse::from(result)))
}

pub(super) async fn list_safeline_sites_handler(
    State(state): State<ApiState>,
    ExtractJson(payload): ExtractJson<SafeLineTestRequest>,
) -> ApiResult<Json<SafeLineSitesResponse>> {
    let sites = crate::integrations::safeline::list_sites(&payload.into_config())
        .await
        .map_err(|err| ApiError::bad_request(err.to_string()))?;
    let (cached_at, cache_status, cache_message) =
        if let Some(store) = state.context.sqlite_store.as_deref() {
            let existing_cache = store
                .list_safeline_cached_sites()
                .await
                .map_err(ApiError::internal)?;
            if sites.is_empty() && !existing_cache.is_empty() {
                (
                    existing_cache.iter().map(|site| site.updated_at).max(),
                    "preserved".to_string(),
                    Some("上游返回空站点列表，已保留现有本地缓存以避免误清空。".to_string()),
                )
            } else {
                (
                    Some(
                        store
                            .replace_safeline_cached_sites(
                                &sites
                                    .iter()
                                    .map(crate::storage::SafeLineCachedSiteUpsert::from_summary)
                                    .collect::<Result<Vec<_>, _>>()
                                    .map_err(ApiError::internal)?,
                            )
                            .await
                            .map_err(ApiError::internal)?,
                    )
                    .flatten(),
                    if sites.is_empty() {
                        "empty".to_string()
                    } else {
                        "fresh".to_string()
                    },
                    None,
                )
            }
        } else {
            (None, "disabled".to_string(), None)
        };

    Ok(Json(SafeLineSitesResponse {
        total: sites.len() as u32,
        cached_at,
        cache_status,
        cache_message,
        sites: sites.into_iter().map(SafeLineSiteResponse::from).collect(),
    }))
}

pub(super) async fn list_cached_safeline_sites_handler(
    State(state): State<ApiState>,
) -> ApiResult<Json<SafeLineSitesResponse>> {
    let Some(store) = state.context.sqlite_store.as_deref() else {
        return Ok(Json(SafeLineSitesResponse {
            total: 0,
            cached_at: None,
            cache_status: "disabled".to_string(),
            cache_message: None,
            sites: Vec::new(),
        }));
    };
    let cached_sites = store
        .list_safeline_cached_sites()
        .await
        .map_err(ApiError::internal)?;
    let cached_at = cached_sites.iter().map(|site| site.updated_at).max();
    let sites = cached_sites
        .into_iter()
        .map(SafeLineSiteResponse::try_from)
        .collect::<Result<Vec<_>, _>>()
        .map_err(ApiError::internal)?;

    Ok(Json(SafeLineSitesResponse {
        total: sites.len() as u32,
        cached_at,
        cache_status: if sites.is_empty() {
            "empty".to_string()
        } else {
            "cached".to_string()
        },
        cache_message: None,
        sites,
    }))
}

pub(super) async fn list_safeline_mappings_handler(
    State(state): State<ApiState>,
) -> ApiResult<Json<SafeLineMappingsResponse>> {
    let store = sqlite_store(&state)?;
    let mappings = store
        .list_safeline_site_mappings()
        .await
        .map_err(ApiError::internal)?;

    Ok(Json(SafeLineMappingsResponse {
        total: mappings.len() as u32,
        mappings: mappings
            .into_iter()
            .map(SafeLineMappingResponse::from)
            .collect(),
    }))
}

pub(super) async fn update_safeline_mappings_handler(
    State(state): State<ApiState>,
    ExtractJson(payload): ExtractJson<SafeLineMappingsUpdateRequest>,
) -> ApiResult<Json<WriteStatusResponse>> {
    let store = sqlite_store(&state)?;
    let (mappings, allow_empty_replace) = payload
        .into_storage_mappings()
        .map_err(ApiError::bad_request)?;
    if mappings.is_empty() && !allow_empty_replace {
        return Err(ApiError::bad_request(
            "映射更新请求为空。若确实要清空映射，请显式传入 allow_empty_replace=true。".to_string(),
        ));
    }
    store
        .replace_safeline_site_mappings(&mappings)
        .await
        .map_err(ApiError::internal)?;

    Ok(Json(WriteStatusResponse {
        success: true,
        message: "雷池站点映射已写入数据库。".to_string(),
    }))
}

pub(super) async fn list_site_sync_links_handler(
    State(state): State<ApiState>,
) -> ApiResult<Json<SiteSyncLinksResponse>> {
    let store = sqlite_store(&state)?;
    let links = store
        .list_site_sync_links()
        .await
        .map_err(ApiError::internal)?;

    Ok(Json(SiteSyncLinksResponse {
        total: links.len() as u32,
        links: links.into_iter().map(SiteSyncLinkResponse::from).collect(),
    }))
}

pub(super) async fn upsert_site_sync_link_handler(
    State(state): State<ApiState>,
    ExtractJson(payload): ExtractJson<SiteSyncLinkUpsertRequest>,
) -> ApiResult<Json<WriteStatusResponse>> {
    let store = sqlite_store(&state)?;
    let link = payload
        .into_storage_link(store)
        .await
        .map_err(ApiError::bad_request)?;
    store
        .upsert_site_sync_link(&link)
        .await
        .map_err(map_storage_write_error)?;

    Ok(Json(WriteStatusResponse {
        success: true,
        message: format!(
            "同步链路已写入，provider={}, local_site_id={}",
            link.provider, link.local_site_id
        ),
    }))
}

pub(super) async fn delete_site_sync_link_handler(
    State(state): State<ApiState>,
    Path(id): Path<i64>,
) -> ApiResult<Json<WriteStatusResponse>> {
    let store = sqlite_store(&state)?;
    let deleted = store
        .delete_site_sync_link(id)
        .await
        .map_err(ApiError::internal)?;

    if deleted {
        Ok(Json(WriteStatusResponse {
            success: true,
            message: format!("同步链路 {} 已删除。", id),
        }))
    } else {
        Err(ApiError::not_found(format!("同步链路 '{}' 不存在", id)))
    }
}

pub(super) async fn pull_safeline_sites_handler(
    State(state): State<ApiState>,
) -> ApiResult<Json<SafeLineSitesPullResponse>> {
    let store = sqlite_store(&state)?;
    let config = persisted_config(&state).await?;
    let safeline = &config.integrations.safeline;

    if !safeline.enabled {
        return Err(ApiError::conflict("雷池集成尚未启用".to_string()));
    }

    let result = crate::integrations::safeline_sync::pull_sites(store, safeline)
        .await
        .map_err(|err| ApiError::bad_request(err.to_string()))?;

    Ok(Json(SafeLineSitesPullResponse {
        success: true,
        imported_sites: result.imported_sites as u32,
        updated_sites: result.updated_sites as u32,
        imported_certificates: result.imported_certificates as u32,
        updated_certificates: result.updated_certificates as u32,
        linked_sites: result.linked_sites as u32,
        skipped_sites: result.skipped_sites as u32,
        message: format!(
            "雷池站点缓存刷新完成，新增缓存 {} 条、更新缓存 {} 条。本次不会覆盖本地站点配置。",
            result.imported_sites, result.updated_sites,
        ),
    }))
}

pub(super) async fn pull_safeline_site_handler(
    State(state): State<ApiState>,
    Path(remote_site_id): Path<String>,
    payload: Option<ExtractJson<SafeLineSitePullRequest>>,
) -> ApiResult<Json<WriteStatusResponse>> {
    let store = sqlite_store(&state)?;
    let config = persisted_config(&state).await?;
    let safeline = &config.integrations.safeline;

    if !safeline.enabled {
        return Err(ApiError::conflict("雷池集成尚未启用".to_string()));
    }

    let options = payload
        .map(
            |item| crate::integrations::safeline_sync::SafeLineSitePullOptions {
                name: item.options.name,
                primary_hostname: item.options.primary_hostname,
                hostnames: item.options.hostnames,
                listen_ports: item.options.listen_ports,
                upstreams: item.options.upstreams,
                enabled: item.options.enabled,
            },
        )
        .unwrap_or_default();

    let result =
        crate::integrations::safeline_sync::pull_site(store, safeline, &remote_site_id, options)
            .await
            .map_err(|err| ApiError::bad_request(err.to_string()))?;

    Ok(Json(WriteStatusResponse {
        success: true,
        message: match result.action {
            crate::integrations::safeline_sync::SingleSiteSyncAction::Created => format!(
                "雷池站点 {} 已写入本地缓存，本次不会覆盖本地站点配置。",
                result.remote_site_id
            ),
            crate::integrations::safeline_sync::SingleSiteSyncAction::Updated => format!(
                "雷池站点 {} 的本地缓存已刷新，本次不会覆盖本地站点配置。",
                result.remote_site_id
            ),
        },
    }))
}

pub(super) async fn push_safeline_sites_handler(
    State(state): State<ApiState>,
) -> ApiResult<Json<SafeLineSitesPushResponse>> {
    let store = sqlite_store(&state)?;
    let config = persisted_config(&state).await?;
    let safeline = &config.integrations.safeline;

    if !safeline.enabled {
        return Err(ApiError::conflict("雷池集成尚未启用".to_string()));
    }

    let result = crate::integrations::safeline_sync::push_sites(store, safeline)
        .await
        .map_err(|err| ApiError::bad_request(err.to_string()))?;

    Ok(Json(SafeLineSitesPushResponse {
        success: true,
        created_sites: result.created_sites as u32,
        updated_sites: result.updated_sites as u32,
        created_certificates: result.created_certificates as u32,
        reused_certificates: result.reused_certificates as u32,
        skipped_sites: result.skipped_sites as u32,
        failed_sites: result.failed_sites as u32,
        message: format!(
            "本地站点推送完成，新建站点 {} 个、更新站点 {} 个，证书新建 {} 个，失败 {} 个。",
            result.created_sites,
            result.updated_sites,
            result.created_certificates,
            result.failed_sites
        ),
    }))
}

pub(super) async fn push_safeline_site_handler(
    State(state): State<ApiState>,
    Path(local_site_id): Path<i64>,
) -> ApiResult<Json<WriteStatusResponse>> {
    let store = sqlite_store(&state)?;
    let config = persisted_config(&state).await?;
    let safeline = &config.integrations.safeline;

    if !safeline.enabled {
        return Err(ApiError::conflict("雷池集成尚未启用".to_string()));
    }

    let result = crate::integrations::safeline_sync::push_site(store, safeline, local_site_id)
        .await
        .map_err(|err| ApiError::bad_request(err.to_string()))?;

    Ok(Json(WriteStatusResponse {
        success: true,
        message: match result.action {
            crate::integrations::safeline_sync::SingleSiteSyncAction::Created => format!(
                "本地站点 #{} 已创建到雷池站点 {}。",
                result.local_site_id, result.remote_site_id
            ),
            crate::integrations::safeline_sync::SingleSiteSyncAction::Updated => format!(
                "本地站点 #{} 已推送更新到雷池站点 {}。",
                result.local_site_id, result.remote_site_id
            ),
        },
    }))
}

pub(super) async fn pull_safeline_certificates_handler(
    State(state): State<ApiState>,
) -> ApiResult<Json<SafeLineCertificatesPullResponse>> {
    let store = sqlite_store(&state)?;
    let config = persisted_config(&state).await?;
    let safeline = &config.integrations.safeline;

    if !safeline.enabled {
        return Err(ApiError::conflict("雷池集成尚未启用".to_string()));
    }

    let result = crate::integrations::safeline_sync::pull_certificates(store, safeline)
        .await
        .map_err(|err| ApiError::bad_request(err.to_string()))?;

    Ok(Json(SafeLineCertificatesPullResponse {
        success: true,
        imported_certificates: result.imported_certificates as u32,
        updated_certificates: result.updated_certificates as u32,
        skipped_certificates: result.skipped_certificates as u32,
        message: format!(
            "雷池证书同步完成，新增 {} 张、更新 {} 张。",
            result.imported_certificates, result.updated_certificates
        ),
    }))
}

pub(super) async fn pull_safeline_certificate_handler(
    State(state): State<ApiState>,
    Path(remote_cert_id): Path<String>,
) -> ApiResult<Json<WriteStatusResponse>> {
    let store = sqlite_store(&state)?;
    let config = persisted_config(&state).await?;
    let safeline = &config.integrations.safeline;

    if !safeline.enabled {
        return Err(ApiError::conflict("雷池集成尚未启用".to_string()));
    }

    let local_id =
        crate::integrations::safeline_sync::pull_certificate(store, safeline, &remote_cert_id)
            .await
            .map_err(|err| ApiError::bad_request(err.to_string()))?;

    Ok(Json(WriteStatusResponse {
        success: true,
        message: format!(
            "雷池证书 {} 已同步到本地证书 #{}。",
            remote_cert_id, local_id
        ),
    }))
}

pub(super) async fn push_safeline_certificate_handler(
    State(state): State<ApiState>,
    Path(local_certificate_id): Path<i64>,
) -> ApiResult<Json<WriteStatusResponse>> {
    let store = sqlite_store(&state)?;
    let config = persisted_config(&state).await?;
    let safeline = &config.integrations.safeline;

    if !safeline.enabled {
        return Err(ApiError::conflict("雷池集成尚未启用".to_string()));
    }

    let remote_id =
        crate::integrations::safeline_sync::push_certificate(store, safeline, local_certificate_id)
            .await
            .map_err(|err| ApiError::bad_request(err.to_string()))?;

    Ok(Json(WriteStatusResponse {
        success: true,
        message: format!(
            "本地证书 #{} 已同步到雷池证书 {}。",
            local_certificate_id, remote_id
        ),
    }))
}

pub(super) async fn preview_safeline_certificate_match_handler(
    State(state): State<ApiState>,
    Path(local_certificate_id): Path<i64>,
) -> ApiResult<Json<SafeLineCertificateMatchPreviewResponse>> {
    let store = sqlite_store(&state)?;
    let config = persisted_config(&state).await?;
    let safeline = &config.integrations.safeline;

    if !safeline.enabled {
        return Err(ApiError::conflict("雷池集成尚未启用".to_string()));
    }

    let preview = crate::integrations::safeline_sync::preview_certificate_match(
        store,
        safeline,
        local_certificate_id,
    )
    .await
    .map_err(|err| ApiError::bad_request(err.to_string()))?;

    Ok(Json(SafeLineCertificateMatchPreviewResponse {
        success: true,
        status: preview.status,
        strategy: preview.strategy,
        local_certificate_id: preview.local_certificate_id,
        local_domains: preview.local_domains,
        linked_remote_id: preview.linked_remote_id,
        matched_remote_id: preview.matched_remote_id,
        message: preview.message,
        candidates: preview
            .candidates
            .into_iter()
            .map(|item| SafeLineCertificateMatchCandidateResponse {
                id: item.id,
                domains: item.domains,
                issuer: item.issuer,
                valid_to: item.valid_to,
                related_sites: item.related_sites,
            })
            .collect(),
    }))
}

pub(super) async fn sync_safeline_events_handler(
    State(state): State<ApiState>,
) -> ApiResult<Json<SafeLineEventSyncResponse>> {
    let store = sqlite_store(&state)?;
    let config = persisted_config(&state).await?;
    let safeline = &config.integrations.safeline;

    if !safeline.enabled {
        return Err(ApiError::conflict("雷池集成尚未启用".to_string()));
    }

    let result = crate::integrations::safeline_sync::sync_events(store, safeline)
        .await
        .map_err(|err| ApiError::bad_request(err.to_string()))?;

    Ok(Json(SafeLineEventSyncResponse {
        success: true,
        imported: result.imported as u32,
        skipped: result.skipped as u32,
        last_cursor: result.last_cursor,
        message: format!(
            "雷池事件同步完成，新增 {} 条，跳过 {} 条重复事件。",
            result.imported, result.skipped
        ),
    }))
}

pub(super) async fn get_safeline_sync_state_handler(
    State(state): State<ApiState>,
) -> ApiResult<Json<SafeLineSyncOverviewResponse>> {
    let store = sqlite_store(&state)?;
    let events = store
        .load_safeline_sync_state("events")
        .await
        .map_err(ApiError::internal)?;
    let blocked_ips_push = store
        .load_safeline_sync_state("blocked_ips_push")
        .await
        .map_err(ApiError::internal)?;
    let blocked_ips_pull = store
        .load_safeline_sync_state("blocked_ips_pull")
        .await
        .map_err(ApiError::internal)?;
    let blocked_ips_delete = store
        .load_safeline_sync_state("blocked_ips_delete")
        .await
        .map_err(ApiError::internal)?;

    Ok(Json(SafeLineSyncOverviewResponse {
        events: events.map(SafeLineSyncStateResponse::from),
        blocked_ips_push: blocked_ips_push.map(SafeLineSyncStateResponse::from),
        blocked_ips_pull: blocked_ips_pull.map(SafeLineSyncStateResponse::from),
        blocked_ips_delete: blocked_ips_delete.map(SafeLineSyncStateResponse::from),
    }))
}

pub(super) async fn sync_safeline_blocked_ips_handler(
    State(state): State<ApiState>,
) -> ApiResult<Json<SafeLineBlocklistSyncResponse>> {
    let store = sqlite_store(&state)?;
    let config = persisted_config(&state).await?;
    let safeline = &config.integrations.safeline;

    if !safeline.enabled {
        return Err(ApiError::conflict("雷池集成尚未启用".to_string()));
    }

    let result = crate::integrations::safeline_sync::push_blocked_ips(store, safeline)
        .await
        .map_err(|err| ApiError::bad_request(err.to_string()))?;

    Ok(Json(SafeLineBlocklistSyncResponse {
        success: true,
        synced: result.synced as u32,
        skipped: result.skipped as u32,
        failed: result.failed as u32,
        last_cursor: result.last_cursor,
        message: format!(
            "封禁联动完成，成功同步 {} 条，跳过 {} 条重复记录，失败 {} 条。",
            result.synced, result.skipped, result.failed
        ),
    }))
}

pub(super) async fn pull_safeline_blocked_ips_handler(
    State(state): State<ApiState>,
) -> ApiResult<Json<SafeLineBlocklistPullResponse>> {
    let store = sqlite_store(&state)?;
    let config = persisted_config(&state).await?;
    let safeline = &config.integrations.safeline;

    if !safeline.enabled {
        return Err(ApiError::conflict("雷池集成尚未启用".to_string()));
    }

    let result = crate::integrations::safeline_sync::pull_blocked_ips(store, safeline)
        .await
        .map_err(|err| ApiError::bad_request(err.to_string()))?;

    Ok(Json(SafeLineBlocklistPullResponse {
        success: true,
        imported: result.imported as u32,
        skipped: result.skipped as u32,
        last_cursor: result.last_cursor,
        message: format!(
            "封禁回流完成，新增 {} 条，跳过 {} 条重复记录。",
            result.imported, result.skipped
        ),
    }))
}
