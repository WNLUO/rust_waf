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
        state.context.l4_inspector.is_some(),
    )))
}

pub(super) async fn get_l7_config_handler(
    State(state): State<ApiState>,
) -> ApiResult<Json<L7ConfigResponse>> {
    let config = persisted_config(&state).await?;
    Ok(Json(L7ConfigResponse::from_config(
        &config,
        state.context.l7_inspector.is_some(),
    )))
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

    Ok(Json(WriteStatusResponse {
        success: true,
        message: "L4 配置已写入数据库。当前运行中的四层检测实例需重启服务后才会加载新参数。"
            .to_string(),
    }))
}

pub(super) async fn update_l7_config_handler(
    State(state): State<ApiState>,
    ExtractJson(payload): ExtractJson<L7ConfigUpdateRequest>,
) -> ApiResult<Json<WriteStatusResponse>> {
    let store = sqlite_store(&state)?;
    let current = persisted_config(&state).await?;
    let next = payload.into_config(current).map_err(ApiError::bad_request)?;

    store
        .upsert_app_config(&next)
        .await
        .map_err(ApiError::internal)?;

    Ok(Json(WriteStatusResponse {
        success: true,
        message: "L7 配置已写入数据库。监听、代理与协议栈相关参数需重启服务后生效。".to_string(),
    }))
}

pub(super) async fn update_settings_handler(
    State(state): State<ApiState>,
    ExtractJson(payload): ExtractJson<SettingsUpdateRequest>,
) -> ApiResult<Json<WriteStatusResponse>> {
    let store = sqlite_store(&state)?;
    let current = persisted_config(&state).await?;
    let next = payload
        .into_config(current, Some(store))
        .await
        .map_err(ApiError::bad_request)?;

    store
        .upsert_app_config(&next)
        .await
        .map_err(ApiError::internal)?;

    Ok(Json(WriteStatusResponse {
        success: true,
        message: "设置已写入数据库。运行时监听与转发类参数需重启服务后生效。".to_string(),
    }))
}

pub(super) async fn get_l4_stats_handler(
    State(state): State<ApiState>,
) -> ApiResult<Json<L4StatsResponse>> {
    let response = state
        .context
        .l4_inspector
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
