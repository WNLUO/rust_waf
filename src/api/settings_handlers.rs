use super::*;

pub(super) async fn get_settings_handler(
    State(state): State<ApiState>,
) -> ApiResult<Json<SettingsResponse>> {
    let config = persisted_config(&state).await?;
    Ok(Json(SettingsResponse::from_config(&config)))
}

pub(super) async fn get_l4_config_handler(
    State(state): State<ApiState>,
) -> ApiResult<Json<L4ConfigResponse>> {
    let config = persisted_config(&state).await?;
    Ok(Json(L4ConfigResponse::from_config(
        &config,
        state.context.l4_runtime_enabled(),
    )))
}

pub(super) async fn get_l7_config_handler(
    State(state): State<ApiState>,
) -> ApiResult<Json<L7ConfigResponse>> {
    let config = persisted_config(&state).await?;
    Ok(Json(L7ConfigResponse::from_config(&config, true)))
}

pub(super) async fn get_global_settings_handler(
    State(state): State<ApiState>,
) -> ApiResult<Json<GlobalSettingsResponse>> {
    let config = persisted_config(&state).await?;
    Ok(Json(GlobalSettingsResponse::from_config(&config)))
}

pub(super) async fn update_l4_config_handler(
    State(state): State<ApiState>,
    ExtractJson(payload): ExtractJson<L4ConfigUpdateRequest>,
) -> ApiResult<Json<WriteStatusResponse>> {
    let store = sqlite_store(&state)?;
    let current = persisted_config(&state).await?;
    let next = payload.into_config(current);

    store
        .upsert_app_config(&next)
        .await
        .map_err(ApiError::internal)?;
    state.context.apply_runtime_config(next.clone());
    state
        .context
        .refresh_l4_runtime_from_config()
        .await
        .map_err(ApiError::internal)?;

    Ok(Json(WriteStatusResponse {
        success: true,
        message: "L4 配置已写入数据库，并已立即刷新运行中的四层检测参数。"
            .to_string(),
    }))
}

pub(super) async fn update_l7_config_handler(
    State(state): State<ApiState>,
    ExtractJson(payload): ExtractJson<L7ConfigUpdateRequest>,
) -> ApiResult<Json<WriteStatusResponse>> {
    let store = sqlite_store(&state)?;
    let current = persisted_config(&state).await?;
    let previous = current.clone();
    let next = payload
        .into_config(current)
        .map_err(ApiError::bad_request)?;

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

    Ok(Json(WriteStatusResponse {
        success: true,
        message: if previous.listen_addrs != next.listen_addrs
            || previous.http3_config.listen_addr != next.http3_config.listen_addr
        {
            "HTTP 接入与代理配置已写入数据库。代理超时、真实来源解析、上游策略和站点/证书路由已立即刷新；监听地址与 HTTP/3 监听变更仍需重启服务生效。".to_string()
        } else {
            "HTTP 接入与代理配置已写入数据库，并已立即刷新运行时代理参数与站点/证书路由。"
                .to_string()
        },
    }))
}

pub(super) async fn update_settings_handler(
    State(state): State<ApiState>,
    ExtractJson(payload): ExtractJson<SettingsUpdateRequest>,
) -> ApiResult<Json<WriteStatusResponse>> {
    let store = sqlite_store(&state)?;
    let current = persisted_config(&state).await?;
    let previous = current.clone();
    let next = payload
        .into_config(current, Some(store))
        .await
        .map_err(ApiError::bad_request)?;

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

    Ok(Json(WriteStatusResponse {
        success: true,
        message: if previous.gateway_config.https_listen_addr
            != next.gateway_config.https_listen_addr
            || previous.api_bind != next.api_bind
        {
            "系统设置已写入数据库。默认证书、上游地址与 SafeLine 配置已立即刷新；HTTPS/API 监听地址变更仍需重启服务生效。".to_string()
        } else {
            "系统设置已写入数据库，并已立即刷新默认证书、上游地址与 SafeLine 运行时配置。"
                .to_string()
        },
    }))
}

pub(super) async fn update_global_settings_handler(
    State(state): State<ApiState>,
    ExtractJson(payload): ExtractJson<GlobalSettingsUpdateRequest>,
) -> ApiResult<Json<WriteStatusResponse>> {
    let store = sqlite_store(&state)?;
    let current = persisted_config(&state).await?;
    let next = payload
        .into_config(current)
        .map_err(ApiError::bad_request)?;

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

    Ok(Json(WriteStatusResponse {
        success: true,
        message: "全局设置已保存，并已立即刷新源 IP 解析、转发头与响应策略。".to_string(),
    }))
}

pub(super) async fn get_l4_stats_handler(
    State(state): State<ApiState>,
) -> ApiResult<Json<L4StatsResponse>> {
    let response = state
        .context
        .l4_inspector()
        .as_ref()
        .map(|inspector| L4StatsResponse::from_stats(inspector.get_statistics()))
        .unwrap_or_else(L4StatsResponse::disabled);

    Ok(Json(response))
}

pub(super) async fn get_l7_stats_handler(
    State(state): State<ApiState>,
) -> ApiResult<Json<L7StatsResponse>> {
    Ok(Json(L7StatsResponse::from_context(state.context.as_ref())))
}
