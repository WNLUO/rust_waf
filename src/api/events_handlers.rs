use super::*;

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

pub(super) async fn delete_blocked_ip_handler(
    State(state): State<ApiState>,
    Path(id): Path<i64>,
) -> ApiResult<Json<WriteStatusResponse>> {
    let store = sqlite_store(&state)?;
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

        Ok(Json(WriteStatusResponse {
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
        }))
    } else {
        Err(ApiError::not_found(format!(
            "Blocked IP record '{}' not found",
            id
        )))
    }
}
