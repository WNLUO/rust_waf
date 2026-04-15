use super::*;
use std::collections::HashSet;
use std::time::Duration;

pub(super) async fn list_security_events_handler(
    State(state): State<ApiState>,
    Query(params): Query<EventsQueryParams>,
) -> ApiResult<Json<SecurityEventsResponse>> {
    let store = sqlite_store(&state)?;
    let result = store
        .list_security_events(&params.into_query().map_err(ApiError::bad_request)?)
        .await
        .map_err(ApiError::internal)?;

    Ok(Json(SecurityEventsResponse {
        total: result.total,
        limit: result.limit,
        offset: result.offset,
        events: result
            .items
            .into_iter()
            .map(SecurityEventResponse::from)
            .collect(),
    }))
}

pub(super) async fn list_behavior_profiles_handler(
    State(state): State<ApiState>,
) -> ApiResult<Json<BehaviorProfilesResponse>> {
    let profiles = state.context.l7_behavior_guard().snapshot_profiles(256);
    let store = state.context.sqlite_store.as_ref().cloned();
    let mut response_profiles = Vec::with_capacity(profiles.len());
    for profile in profiles {
        let mut response = BehaviorProfileResponse::from(profile);
        if let (Some(store), Some(source_ip)) = (store.as_ref(), response.source_ip.as_deref()) {
            if let Some(entry) = store
                .load_active_local_blocked_ip_by_ip(source_ip)
                .await
                .map_err(ApiError::internal)?
            {
                response.blocked = true;
                response.blocked_at = Some(entry.blocked_at);
                response.blocked_expires_at = Some(entry.expires_at);
                response.blocked_reason = Some(entry.reason);
            }
        }
        response_profiles.push(response);
    }
    Ok(Json(BehaviorProfilesResponse {
        total: response_profiles.len() as u64,
        profiles: response_profiles,
    }))
}

pub(super) async fn update_security_event_handler(
    State(state): State<ApiState>,
    Path(id): Path<i64>,
    ExtractJson(payload): ExtractJson<EventUpdateRequest>,
) -> ApiResult<Json<WriteStatusResponse>> {
    let store = sqlite_store(&state)?;
    let updated = store
        .mark_security_event_handled(id, payload.handled)
        .await
        .map_err(ApiError::internal)?;

    if updated {
        Ok(Json(WriteStatusResponse {
            success: true,
            message: format!(
                "Security event {} marked as {}",
                id,
                if payload.handled {
                    "handled"
                } else {
                    "unhandled"
                }
            ),
        }))
    } else {
        Err(ApiError::not_found(format!(
            "Security event '{}' not found",
            id
        )))
    }
}

pub(super) async fn list_blocked_ips_handler(
    State(state): State<ApiState>,
    Query(params): Query<BlockedIpsQueryParams>,
) -> ApiResult<Json<BlockedIpsResponse>> {
    let store = sqlite_store(&state)?;
    let result = store
        .list_blocked_ips(&params.into_query().map_err(ApiError::bad_request)?)
        .await
        .map_err(ApiError::internal)?;

    Ok(Json(BlockedIpsResponse {
        total: result.total,
        limit: result.limit,
        offset: result.offset,
        blocked_ips: result
            .items
            .into_iter()
            .map(BlockedIpResponse::from)
            .collect(),
    }))
}

pub(super) async fn cleanup_expired_blocked_ips_handler(
    State(state): State<ApiState>,
    ExtractJson(payload): ExtractJson<BlockedIpsCleanupExpiredRequest>,
) -> ApiResult<Json<BlockedIpsCleanupExpiredResponse>> {
    let store = sqlite_store(&state)?;
    let source_scope = parse_blocked_ip_source_scope_param(payload.source_scope.as_deref())
        .map_err(ApiError::bad_request)?;
    let provider = payload.provider.and_then(|value| {
        let normalized = value.trim().to_string();
        (!normalized.is_empty() && normalized != "all").then_some(normalized)
    });
    let expires_before = payload.expires_before.unwrap_or_else(unix_timestamp);
    let cleanup_query = crate::storage::BlockedIpCleanupQuery {
        source_scope,
        provider,
        blocked_from: payload.blocked_from,
        blocked_to: payload.blocked_to,
        expires_before,
    };

    let cleaned_items = store
        .cleanup_expired_blocked_ips(&cleanup_query)
        .await
        .map_err(ApiError::internal)?;
    let mut runtime_unblocked = 0_u32;
    for item in &cleaned_items {
        if item.provider.is_none() {
            match item.ip.parse::<std::net::IpAddr>() {
                Ok(ip) => {
                    let removed = state
                        .context
                        .l4_inspector()
                        .as_ref()
                        .map(|inspector| inspector.unblock_ip(&ip))
                        .unwrap_or(false);
                    if removed {
                        runtime_unblocked = runtime_unblocked.saturating_add(1);
                    }
                }
                Err(err) => {
                    log::warn!(
                        "Failed to parse blocked IP '{}' while cleanup runtime unblock: {}",
                        item.ip,
                        err
                    );
                }
            }
        }
        store.emit_blocked_ip_deleted(item.id);
    }

    let cleaned = cleaned_items.len() as u32;
    Ok(Json(BlockedIpsCleanupExpiredResponse {
        success: true,
        cleaned,
        runtime_unblocked,
        message: if cleaned == 0 {
            "没有匹配到可清理的过期封禁记录。".to_string()
        } else {
            format!(
                "已清理 {} 条过期封禁记录，其中运行时同步解除 {} 条。",
                cleaned, runtime_unblocked
            )
        },
    }))
}

pub(super) async fn create_blocked_ip_handler(
    State(state): State<ApiState>,
    ExtractJson(payload): ExtractJson<BlockedIpCreateRequest>,
) -> ApiResult<Json<WriteStatusResponse>> {
    let store = sqlite_store(&state)?;
    let ip_text = payload.ip.trim();
    if ip_text.is_empty() {
        return Err(ApiError::bad_request("IP 不能为空".to_string()));
    }

    let ip = ip_text
        .parse::<std::net::IpAddr>()
        .map_err(|_| ApiError::bad_request(format!("无效的 IP 地址 '{}'", ip_text)))?;
    let reason = payload.reason.trim();
    if reason.is_empty() {
        return Err(ApiError::bad_request("封禁原因不能为空".to_string()));
    }

    let duration_secs = payload
        .duration_secs
        .unwrap_or(crate::l4::connection::limiter::RATE_LIMIT_BLOCK_DURATION_SECS as u64)
        .clamp(30, 30 * 24 * 3600);
    let blocked_at = unix_timestamp();
    let expires_at = blocked_at
        .checked_add(duration_secs as i64)
        .ok_or_else(|| ApiError::bad_request("封禁时长过大".to_string()))?;

    if let Some(inspector) = state.context.l4_inspector().as_ref() {
        if !inspector.block_ip(&ip, reason, Duration::from_secs(duration_secs)) {
            return Err(ApiError::conflict(
                "运行时封禁池已满，无法新增封禁。请先解除部分封禁后重试。".to_string(),
            ));
        }
    }

    store.enqueue_blocked_ip(crate::storage::BlockedIpRecord::new(
        ip.to_string(),
        reason.to_string(),
        blocked_at,
        expires_at,
    ));
    store.flush().await.map_err(ApiError::internal)?;

    Ok(Json(WriteStatusResponse {
        success: true,
        message: format!("已封禁 IP '{}'，持续 {} 秒。", ip, duration_secs),
    }))
}

pub(super) async fn delete_blocked_ip_handler(
    State(state): State<ApiState>,
    Path(id): Path<i64>,
) -> ApiResult<Json<WriteStatusResponse>> {
    unblock_blocked_ip(&state, id).await.map(Json)
}

pub(super) async fn batch_unblock_blocked_ips_handler(
    State(state): State<ApiState>,
    ExtractJson(payload): ExtractJson<BlockedIpsBatchUnblockRequest>,
) -> ApiResult<Json<BlockedIpsBatchUnblockResponse>> {
    if payload.ids.is_empty() {
        return Err(ApiError::bad_request("至少提供一个待解封 ID".to_string()));
    }
    if payload.ids.len() > 200 {
        return Err(ApiError::bad_request(
            "单次最多批量解封 200 条记录".to_string(),
        ));
    }

    let mut dedup = HashSet::new();
    let ids: Vec<i64> = payload
        .ids
        .into_iter()
        .filter(|id| dedup.insert(*id))
        .collect();
    let requested = ids.len() as u32;
    let mut unblocked = 0_u32;
    let mut failed_ids = Vec::new();

    for id in ids {
        match unblock_blocked_ip(&state, id).await {
            Ok(_) => {
                unblocked = unblocked.saturating_add(1);
            }
            Err(_) => {
                failed_ids.push(id);
            }
        }
    }

    let failed = requested.saturating_sub(unblocked);
    Ok(Json(BlockedIpsBatchUnblockResponse {
        success: failed == 0,
        requested,
        unblocked,
        failed,
        failed_ids,
        message: if failed == 0 {
            format!("批量解封完成，共处理 {} 条。", requested)
        } else {
            format!("批量解封完成：成功 {} 条，失败 {} 条。", unblocked, failed)
        },
    }))
}

async fn unblock_blocked_ip(state: &ApiState, id: i64) -> ApiResult<WriteStatusResponse> {
    let store = sqlite_store(state)?;
    let Some(entry) = store
        .load_blocked_ip(id)
        .await
        .map_err(ApiError::internal)?
    else {
        return Err(ApiError::not_found(format!(
            "Blocked IP record '{}' not found",
            id
        )));
    };

    if entry.provider.as_deref() == Some("safeline") {
        let config = persisted_config(&state).await?;
        let safeline = &config.integrations.safeline;
        if !safeline.enabled {
            return Err(ApiError::conflict(
                "雷池集成尚未启用，无法执行远端解封".to_string(),
            ));
        }

        let result = crate::integrations::safeline::delete_blocked_ip(safeline, &entry)
            .await
            .map_err(|err| ApiError::bad_request(err.to_string()))?;
        if !result.accepted {
            store
                .upsert_safeline_sync_state("blocked_ips_delete", Some(entry.expires_at), 0, 1)
                .await
                .map_err(ApiError::internal)?;
            return Err(ApiError::conflict(format!(
                "雷池远端解封失败，HTTP {}：{}",
                result.status_code, result.message
            )));
        }

        store
            .upsert_safeline_sync_state("blocked_ips_delete", Some(entry.expires_at), 1, 0)
            .await
            .map_err(ApiError::internal)?;
    }

    let deleted = store
        .delete_blocked_ip(id)
        .await
        .map_err(ApiError::internal)?;

    if deleted {
        store.emit_blocked_ip_deleted(id);
        let runtime_unblocked = if entry.provider.is_none() {
            match entry.ip.parse::<std::net::IpAddr>() {
                Ok(ip) => state
                    .context
                    .l4_inspector()
                    .as_ref()
                    .map(|inspector| inspector.unblock_ip(&ip))
                    .unwrap_or(false),
                Err(err) => {
                    log::warn!(
                        "Failed to parse blocked IP '{}' while unblocking runtime state: {}",
                        entry.ip,
                        err
                    );
                    false
                }
            }
        } else {
            false
        };

        Ok(WriteStatusResponse {
            success: true,
            message: if entry.provider.as_deref() == Some("safeline") {
                format!("雷池封禁记录 '{}' 已完成远端解封并从本地缓存移除。", id)
            } else if runtime_unblocked {
                format!(
                    "本地封禁记录 '{}' 已从数据库移除，并同步解除运行时封禁。",
                    id
                )
            } else {
                format!("本地封禁记录 '{}' 已从数据库移除。", id)
            },
        })
    } else {
        Err(ApiError::not_found(format!(
            "Blocked IP record '{}' not found",
            id
        )))
    }
}

fn parse_blocked_ip_source_scope_param(
    value: Option<&str>,
) -> Result<crate::storage::BlockedIpSourceScope, String> {
    match value.unwrap_or("all").trim().to_ascii_lowercase().as_str() {
        "all" => Ok(crate::storage::BlockedIpSourceScope::All),
        "local" => Ok(crate::storage::BlockedIpSourceScope::Local),
        "remote" => Ok(crate::storage::BlockedIpSourceScope::Remote),
        other => Err(format!("Unsupported blocked IP source_scope '{}'", other)),
    }
}
