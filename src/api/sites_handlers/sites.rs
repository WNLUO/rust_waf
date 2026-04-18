use super::super::*;
use std::net::SocketAddr;

pub(in crate::api) async fn list_local_sites_handler(
    State(state): State<ApiState>,
) -> ApiResult<Json<LocalSitesResponse>> {
    let store = sqlite_store(&state)?;
    let sites = store.list_local_sites().await.map_err(ApiError::internal)?;
    let sites = sites
        .into_iter()
        .map(LocalSiteResponse::try_from)
        .collect::<Result<Vec<_>, _>>()
        .map_err(ApiError::internal)?;

    Ok(Json(LocalSitesResponse {
        total: sites.len() as u32,
        sites,
    }))
}

pub(in crate::api) async fn get_global_entry_config_handler(
    State(state): State<ApiState>,
) -> ApiResult<Json<GlobalEntryConfigResponse>> {
    let config = persisted_config(&state).await?;
    Ok(Json(GlobalEntryConfigResponse {
        http_port: display_port(config.listen_addrs.first().map(String::as_str)),
        https_port: display_port(Some(&config.gateway_config.https_listen_addr)),
    }))
}

pub(in crate::api) async fn update_global_entry_config_handler(
    State(state): State<ApiState>,
    ExtractJson(payload): ExtractJson<GlobalEntryConfigUpdateRequest>,
) -> ApiResult<Json<WriteStatusResponse>> {
    let store = sqlite_store(&state)?;
    let current = persisted_config(&state).await?;
    let mut next = current.clone();
    let http_listen_addr = normalize_global_entry_port(&payload.http_port, "HTTP")?;
    let https_listen_addr = normalize_optional_global_entry_port(&payload.https_port, "HTTPS")?;

    next.listen_addrs = vec![http_listen_addr.clone()];
    next.gateway_config.https_listen_addr = https_listen_addr.clone();
    next = next.normalized();

    state.context.apply_runtime_config(next.clone());
    let validation_result =
        crate::core::engine::validate_entry_listener_config(Arc::clone(&state.context)).await;
    state.context.apply_runtime_config(current.clone());
    validation_result.map_err(|err| ApiError::bad_request(err.to_string()))?;

    store
        .upsert_app_config(&next)
        .await
        .map_err(ApiError::internal)?;
    state.context.apply_runtime_config(next.clone());
    state
        .context
        .refresh_gateway_runtime_from_storage()
        .await
        .map_err(ApiError::internal)?;
    crate::core::engine::sync_entry_listener_runtime(
        Arc::clone(&state.context),
        next.max_concurrent_tasks.saturating_mul(4).clamp(128, 4096),
        next.max_concurrent_tasks,
    )
    .await
    .map_err(ApiError::internal)?;

    Ok(Json(WriteStatusResponse {
        success: true,
        message: format!(
            "全局入口已更新，HTTP {} 与 HTTPS {} 已立即接管监听。",
            http_listen_addr,
            if https_listen_addr.is_empty() {
                "已关闭".to_string()
            } else {
                https_listen_addr
            }
        ),
    }))
}

pub(in crate::api) async fn get_local_site_handler(
    State(state): State<ApiState>,
    Path(id): Path<i64>,
) -> ApiResult<Json<LocalSiteResponse>> {
    let store = sqlite_store(&state)?;
    let site = store
        .load_local_site(id)
        .await
        .map_err(ApiError::internal)?;
    match site {
        Some(site) => Ok(Json(
            LocalSiteResponse::try_from(site).map_err(ApiError::internal)?,
        )),
        None => Err(ApiError::not_found(format!("本地站点 '{}' 不存在", id))),
    }
}

pub(in crate::api) async fn create_local_site_handler(
    State(state): State<ApiState>,
    ExtractJson(payload): ExtractJson<LocalSiteUpsertRequest>,
) -> ApiResult<(StatusCode, Json<LocalSiteResponse>)> {
    let store = sqlite_store(&state)?;
    let site = payload
        .into_storage_site(store)
        .await
        .map_err(ApiError::bad_request)?;
    let id = store
        .insert_local_site(&site)
        .await
        .map_err(map_storage_write_error)?;
    let created = store
        .load_local_site(id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::internal("新建站点后未能重新读取记录"))?;
    state
        .context
        .refresh_gateway_runtime_from_storage()
        .await
        .map_err(ApiError::internal)?;

    Ok((
        StatusCode::CREATED,
        Json(LocalSiteResponse::try_from(created).map_err(ApiError::internal)?),
    ))
}

pub(in crate::api) async fn update_local_site_handler(
    State(state): State<ApiState>,
    Path(id): Path<i64>,
    ExtractJson(payload): ExtractJson<LocalSiteUpsertRequest>,
) -> ApiResult<Json<WriteStatusResponse>> {
    let store = sqlite_store(&state)?;
    let current = store
        .load_local_site(id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found(format!("本地站点 '{}' 不存在", id)))?;
    if let Some(expected_updated_at) = payload.expected_updated_at {
        if current.updated_at != expected_updated_at {
            return Err(ApiError::conflict(format!(
                "本地站点 {} 已被其他操作更新，请刷新页面后重试。",
                id
            )));
        }
    }
    let site = payload
        .into_storage_site(store)
        .await
        .map_err(ApiError::bad_request)?;
    let updated = store
        .update_local_site(id, &site)
        .await
        .map_err(map_storage_write_error)?;

    if updated {
        state
            .context
            .refresh_gateway_runtime_from_storage()
            .await
            .map_err(ApiError::internal)?;
        Ok(Json(WriteStatusResponse {
            success: true,
            message: format!("本地站点 {} 已更新，并已立即刷新路由匹配。", id),
        }))
    } else {
        Err(ApiError::not_found(format!("本地站点 '{}' 不存在", id)))
    }
}

pub(in crate::api) async fn delete_local_site_handler(
    State(state): State<ApiState>,
    Path(id): Path<i64>,
) -> ApiResult<Json<WriteStatusResponse>> {
    let store = sqlite_store(&state)?;
    let deleted = store
        .delete_local_site(id)
        .await
        .map_err(ApiError::internal)?;

    if deleted {
        state
            .context
            .refresh_gateway_runtime_from_storage()
            .await
            .map_err(ApiError::internal)?;
        Ok(Json(WriteStatusResponse {
            success: true,
            message: format!("本地站点 {} 已删除，并已立即刷新路由匹配。", id),
        }))
    } else {
        Err(ApiError::not_found(format!("本地站点 '{}' 不存在", id)))
    }
}

pub(in crate::api) async fn clear_local_site_data_handler(
    State(state): State<ApiState>,
) -> ApiResult<Json<WriteStatusResponse>> {
    let store = sqlite_store(&state)?;
    store.clear_site_data().await.map_err(ApiError::internal)?;
    state
        .context
        .refresh_gateway_runtime_from_storage()
        .await
        .map_err(ApiError::internal)?;

    Ok(Json(WriteStatusResponse {
        success: true,
        message: "本地站点、同步链路、雷池站点映射和缓存站点数据已清空。".to_string(),
    }))
}

fn display_port(value: Option<&str>) -> String {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .and_then(|value| value.parse::<SocketAddr>().ok())
        .map(|addr| addr.port().to_string())
        .unwrap_or_default()
}

fn normalize_global_entry_port(value: &str, label: &str) -> Result<String, ApiError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(ApiError::bad_request(format!("{} 入口端口不能为空", label)));
    }
    let port = trimmed.parse::<u16>().map_err(|err| {
        ApiError::bad_request(format!("{} 入口端口 '{}' 无效: {}", label, trimmed, err))
    })?;
    if port == 0 {
        return Err(ApiError::bad_request(format!("{} 入口端口不能为 0", label)));
    }
    Ok(format!("0.0.0.0:{port}"))
}

fn normalize_optional_global_entry_port(value: &str, label: &str) -> Result<String, ApiError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    normalize_global_entry_port(trimmed, label)
}
