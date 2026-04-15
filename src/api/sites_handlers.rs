use super::*;
use std::net::SocketAddr;
use std::path::{Path as StdPath, PathBuf};

const MANAGED_HTTP3_CERT_DIR: &str = "data/http3/managed";

async fn local_certificate_response_with_secret(
    store: &crate::storage::SqliteStore,
    certificate: crate::storage::LocalCertificateEntry,
) -> Result<LocalCertificateResponse, ApiError> {
    let certificate_id = certificate.id;
    let mut response =
        LocalCertificateResponse::try_from(certificate).map_err(ApiError::internal)?;
    if let Some(secret) = store
        .load_local_certificate_secret(certificate_id)
        .await
        .map_err(ApiError::internal)?
    {
        response.certificate_pem = Some(secret.certificate_pem);
        response.private_key_pem = Some(secret.private_key_pem);
    }
    Ok(response)
}

async fn maybe_push_certificate_to_safeline(
    state: &ApiState,
    certificate_id: i64,
    auto_sync_enabled: bool,
) -> Result<Option<String>, ApiError> {
    if !auto_sync_enabled {
        return Ok(None);
    }

    let store = sqlite_store(state)?;
    let config = persisted_config(state).await?;
    let safeline = &config.integrations.safeline;
    if !safeline.enabled {
        return Ok(Some(
            "证书已保存，但雷池集成未启用，已跳过自动同步。".to_string(),
        ));
    }

    let message =
        match crate::integrations::safeline_sync::push_certificate(store, safeline, certificate_id)
            .await
        {
            Ok(remote_id) => format!("证书已自动同步到雷池证书 {}。", remote_id),
            Err(err) => format!("证书已保存，但自动同步到雷池失败：{}", err),
        };

    Ok(Some(message))
}

async fn maybe_configure_http3_managed_certificate(
    state: &ApiState,
    store: &crate::storage::SqliteStore,
    certificate_id: i64,
) -> Result<Option<String>, ApiError> {
    let Some(secret) = store
        .load_local_certificate_secret(certificate_id)
        .await
        .map_err(ApiError::internal)?
    else {
        return Ok(None);
    };

    let cert_path = managed_http3_certificate_path(certificate_id);
    let key_path = managed_http3_private_key_path(certificate_id);
    write_managed_http3_pem_pair(&cert_path, &key_path, &secret).await?;

    let mut config = persisted_config(state).await?;
    let cert_path_string = cert_path.to_string_lossy().to_string();
    let key_path_string = key_path.to_string_lossy().to_string();

    let can_override = config
        .http3_config
        .certificate_path
        .as_deref()
        .map(is_managed_http3_path)
        .unwrap_or(true)
        && config
            .http3_config
            .private_key_path
            .as_deref()
            .map(is_managed_http3_path)
            .unwrap_or(true);

    if !can_override {
        return Ok(Some(
            "检测到 HTTP/3 正在使用自定义证书路径，已保留用户配置，未自动覆盖。".to_string(),
        ));
    }

    let changed = config.http3_config.certificate_path.as_deref()
        != Some(cert_path_string.as_str())
        || config.http3_config.private_key_path.as_deref() != Some(key_path_string.as_str())
        || !config.http3_config.enabled;

    if !changed {
        return Ok(Some(
            "已同步托管证书到 HTTP/3，当前配置无需变更。".to_string(),
        ));
    }

    config.http3_config.certificate_path = Some(cert_path_string);
    config.http3_config.private_key_path = Some(key_path_string);
    config.http3_config.enabled = true;
    let next = config.normalized();

    store
        .upsert_app_config(&next)
        .await
        .map_err(ApiError::internal)?;
    state.context.apply_runtime_config(next);
    #[cfg(feature = "http3")]
    crate::core::engine::sync_http3_listener_runtime(
        Arc::clone(&state.context),
        state
            .context
            .config_snapshot()
            .max_concurrent_tasks
            .saturating_mul(4)
            .clamp(128, 4096),
        state.context.config_snapshot().max_concurrent_tasks,
    )
    .await
    .map_err(ApiError::internal)?;

    Ok(Some(
        "已自动为 HTTP/3 写入证书文件并启用 HTTP/3；QUIC 监听已按当前配置热刷新。".to_string(),
    ))
}

async fn maybe_clear_http3_managed_certificate(
    state: &ApiState,
    store: &crate::storage::SqliteStore,
    certificate_id: i64,
) -> Result<Option<String>, ApiError> {
    let cert_path = managed_http3_certificate_path(certificate_id);
    let key_path = managed_http3_private_key_path(certificate_id);
    remove_file_if_exists(&cert_path).await?;
    remove_file_if_exists(&key_path).await?;

    let mut config = persisted_config(state).await?;
    let cert_path_string = cert_path.to_string_lossy().to_string();
    let key_path_string = key_path.to_string_lossy().to_string();

    let used_by_http3 = config.http3_config.certificate_path.as_deref()
        == Some(cert_path_string.as_str())
        || config.http3_config.private_key_path.as_deref() == Some(key_path_string.as_str());
    if !used_by_http3 {
        return Ok(None);
    }

    config.http3_config.enabled = false;
    config.http3_config.certificate_path = None;
    config.http3_config.private_key_path = None;
    let next = config.normalized();
    store
        .upsert_app_config(&next)
        .await
        .map_err(ApiError::internal)?;
    state.context.apply_runtime_config(next);
    #[cfg(feature = "http3")]
    crate::core::engine::sync_http3_listener_runtime(
        Arc::clone(&state.context),
        state
            .context
            .config_snapshot()
            .max_concurrent_tasks
            .saturating_mul(4)
            .clamp(128, 4096),
        state.context.config_snapshot().max_concurrent_tasks,
    )
    .await
    .map_err(ApiError::internal)?;

    Ok(Some(
        "当前证书已从 HTTP/3 托管配置中移除，并已自动关闭 HTTP/3；如需继续启用，请重新指定证书。"
            .to_string(),
    ))
}

fn managed_http3_certificate_path(certificate_id: i64) -> PathBuf {
    StdPath::new(MANAGED_HTTP3_CERT_DIR).join(format!("cert-{certificate_id}.pem"))
}

fn managed_http3_private_key_path(certificate_id: i64) -> PathBuf {
    StdPath::new(MANAGED_HTTP3_CERT_DIR).join(format!("key-{certificate_id}.pem"))
}

fn is_managed_http3_path(path: &str) -> bool {
    path.starts_with(MANAGED_HTTP3_CERT_DIR)
}

async fn write_managed_http3_pem_pair(
    cert_path: &StdPath,
    key_path: &StdPath,
    secret: &crate::storage::LocalCertificateSecretEntry,
) -> Result<(), ApiError> {
    tokio::fs::create_dir_all(MANAGED_HTTP3_CERT_DIR)
        .await
        .map_err(ApiError::internal)?;
    tokio::fs::write(cert_path, secret.certificate_pem.as_bytes())
        .await
        .map_err(ApiError::internal)?;
    tokio::fs::write(key_path, secret.private_key_pem.as_bytes())
        .await
        .map_err(ApiError::internal)?;
    Ok(())
}

async fn remove_file_if_exists(path: &StdPath) -> Result<(), ApiError> {
    match tokio::fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(ApiError::internal(err)),
    }
}

pub(super) async fn list_local_sites_handler(
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

pub(super) async fn get_global_entry_config_handler(
    State(state): State<ApiState>,
) -> ApiResult<Json<GlobalEntryConfigResponse>> {
    let config = persisted_config(&state).await?;
    Ok(Json(GlobalEntryConfigResponse {
        http_port: display_port(config.listen_addrs.first().map(String::as_str)),
        https_port: display_port(Some(&config.gateway_config.https_listen_addr)),
    }))
}

pub(super) async fn update_global_entry_config_handler(
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

pub(super) async fn get_local_site_handler(
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

pub(super) async fn create_local_site_handler(
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

pub(super) async fn update_local_site_handler(
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

pub(super) async fn delete_local_site_handler(
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

pub(super) async fn clear_local_site_data_handler(
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

pub(super) async fn list_local_certificates_handler(
    State(state): State<ApiState>,
) -> ApiResult<Json<LocalCertificatesResponse>> {
    let store = sqlite_store(&state)?;
    let certificates = store
        .list_local_certificates()
        .await
        .map_err(ApiError::internal)?;
    let certificates = certificates
        .into_iter()
        .map(LocalCertificateResponse::try_from)
        .collect::<Result<Vec<_>, _>>()
        .map_err(ApiError::internal)?;

    Ok(Json(LocalCertificatesResponse {
        total: certificates.len() as u32,
        certificates,
    }))
}

pub(super) async fn get_local_certificate_handler(
    State(state): State<ApiState>,
    Path(id): Path<i64>,
) -> ApiResult<Json<LocalCertificateResponse>> {
    let store = sqlite_store(&state)?;
    let certificate = store
        .load_local_certificate(id)
        .await
        .map_err(ApiError::internal)?;
    match certificate {
        Some(certificate) => Ok(Json(
            local_certificate_response_with_secret(store, certificate).await?,
        )),
        None => Err(ApiError::not_found(format!("本地证书 '{}' 不存在", id))),
    }
}

pub(super) async fn create_local_certificate_handler(
    State(state): State<ApiState>,
    ExtractJson(payload): ExtractJson<LocalCertificateUpsertRequest>,
) -> ApiResult<(StatusCode, Json<LocalCertificateResponse>)> {
    let store = sqlite_store(&state)?;
    let (certificate, secret_update) = payload
        .into_storage_certificate()
        .map_err(ApiError::bad_request)?;
    let id = store
        .insert_local_certificate(&certificate)
        .await
        .map_err(map_storage_write_error)?;
    if let Some(Some(secret)) = secret_update {
        store
            .upsert_local_certificate_secret(id, &secret.certificate_pem, &secret.private_key_pem)
            .await
            .map_err(map_storage_write_error)?;
    }
    let auto_sync_message =
        maybe_push_certificate_to_safeline(&state, id, certificate.auto_sync_enabled).await?;
    let http3_message = maybe_configure_http3_managed_certificate(&state, store, id).await?;
    let created = store
        .load_local_certificate(id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::internal("自动同步后未能重新读取证书记录"))?;
    state
        .context
        .refresh_gateway_runtime_from_storage()
        .await
        .map_err(ApiError::internal)?;

    let mut response = local_certificate_response_with_secret(store, created).await?;
    if let Some(message) = auto_sync_message {
        response.sync_message = if response.sync_message.trim().is_empty() {
            message
        } else {
            format!("{} {}", response.sync_message, message)
        };
    }
    if let Some(message) = http3_message {
        response.sync_message = if response.sync_message.trim().is_empty() {
            message
        } else {
            format!("{} {}", response.sync_message, message)
        };
    }

    Ok((StatusCode::CREATED, Json(response)))
}

pub(super) async fn generate_local_certificate_handler(
    State(state): State<ApiState>,
    ExtractJson(payload): ExtractJson<GeneratedLocalCertificateRequest>,
) -> ApiResult<(StatusCode, Json<LocalCertificateResponse>)> {
    let store = sqlite_store(&state)?;
    let generated = payload
        .into_generated_certificate()
        .map_err(ApiError::bad_request)?;
    let id = store
        .insert_local_certificate(&generated.certificate)
        .await
        .map_err(map_storage_write_error)?;
    store
        .upsert_local_certificate_secret(
            id,
            &generated.secret.certificate_pem,
            &generated.secret.private_key_pem,
        )
        .await
        .map_err(map_storage_write_error)?;
    let http3_message = maybe_configure_http3_managed_certificate(&state, store, id).await?;
    let created = store
        .load_local_certificate(id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::internal("新建证书后未能重新读取记录"))?;
    state
        .context
        .refresh_gateway_runtime_from_storage()
        .await
        .map_err(ApiError::internal)?;

    Ok((
        StatusCode::CREATED,
        Json({
            let mut response = local_certificate_response_with_secret(store, created).await?;
            if let Some(message) = http3_message {
                response.sync_message = if response.sync_message.trim().is_empty() {
                    message
                } else {
                    format!("{} {}", response.sync_message, message)
                };
            }
            response
        }),
    ))
}

pub(super) async fn update_local_certificate_handler(
    State(state): State<ApiState>,
    Path(id): Path<i64>,
    ExtractJson(payload): ExtractJson<LocalCertificateUpsertRequest>,
) -> ApiResult<Json<WriteStatusResponse>> {
    let store = sqlite_store(&state)?;
    let current = store
        .load_local_certificate(id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found(format!("本地证书 '{}' 不存在", id)))?;
    if let Some(expected_updated_at) = payload.expected_updated_at {
        if current.updated_at != expected_updated_at {
            return Err(ApiError::conflict(format!(
                "本地证书 {} 已被其他操作更新，请刷新页面后重试。",
                id
            )));
        }
    }
    let (certificate, secret_update) = payload
        .into_storage_certificate()
        .map_err(ApiError::bad_request)?;
    let updated = store
        .update_local_certificate(id, &certificate)
        .await
        .map_err(map_storage_write_error)?;

    if updated {
        let mut http3_message = None;
        if let Some(secret_update) = secret_update {
            if let Some(secret) = secret_update {
                store
                    .upsert_local_certificate_secret(
                        id,
                        &secret.certificate_pem,
                        &secret.private_key_pem,
                    )
                    .await
                    .map_err(map_storage_write_error)?;
                http3_message =
                    maybe_configure_http3_managed_certificate(&state, store, id).await?;
            } else {
                store
                    .delete_local_certificate_secret(id)
                    .await
                    .map_err(ApiError::internal)?;
                http3_message = maybe_clear_http3_managed_certificate(&state, store, id).await?;
            }
        }
        let auto_sync_message =
            maybe_push_certificate_to_safeline(&state, id, certificate.auto_sync_enabled).await?;
        state
            .context
            .refresh_gateway_runtime_from_storage()
            .await
            .map_err(ApiError::internal)?;
        let mut message = format!("本地证书 {} 已更新，并已立即刷新新连接的证书选择。", id);
        if let Some(extra) = auto_sync_message {
            message.push_str(&extra);
        }
        if let Some(extra) = http3_message {
            message.push_str(&extra);
        }
        Ok(Json(WriteStatusResponse {
            success: true,
            message,
        }))
    } else {
        Err(ApiError::not_found(format!("本地证书 '{}' 不存在", id)))
    }
}

pub(super) async fn bind_local_certificate_remote_handler(
    State(state): State<ApiState>,
    Path(id): Path<i64>,
    ExtractJson(payload): ExtractJson<LocalCertificateRemoteBindRequest>,
) -> ApiResult<Json<WriteStatusResponse>> {
    let store = sqlite_store(&state)?;
    let certificate = store
        .load_local_certificate(id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found(format!("本地证书 '{}' 不存在", id)))?;

    let remote_certificate_id = payload.remote_certificate_id.trim().to_string();
    if remote_certificate_id.is_empty() {
        return Err(ApiError::bad_request(
            "remote_certificate_id 不能为空".to_string(),
        ));
    }

    let updated = crate::storage::LocalCertificateUpsert {
        name: certificate.name.clone(),
        domains: serde_json::from_str(&certificate.domains_json).map_err(ApiError::internal)?,
        issuer: certificate.issuer.clone(),
        valid_from: certificate.valid_from,
        valid_to: certificate.valid_to,
        source_type: certificate.source_type.clone(),
        provider_remote_id: Some(remote_certificate_id.clone()),
        provider_remote_domains: payload.remote_domains,
        last_remote_fingerprint: certificate.last_remote_fingerprint.clone(),
        sync_status: "linked".to_string(),
        sync_message: format!("已手动绑定到雷池证书 {}。", remote_certificate_id),
        auto_sync_enabled: certificate.auto_sync_enabled,
        trusted: certificate.trusted,
        expired: certificate.expired,
        notes: certificate.notes.clone(),
        last_synced_at: certificate.last_synced_at,
    };

    store
        .update_local_certificate(id, &updated)
        .await
        .map_err(map_storage_write_error)?;

    Ok(Json(WriteStatusResponse {
        success: true,
        message: format!(
            "本地证书 #{} 已绑定到雷池证书 {}。",
            id, remote_certificate_id
        ),
    }))
}

pub(super) async fn unbind_local_certificate_remote_handler(
    State(state): State<ApiState>,
    Path(id): Path<i64>,
) -> ApiResult<Json<WriteStatusResponse>> {
    let store = sqlite_store(&state)?;
    let certificate = store
        .load_local_certificate(id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found(format!("本地证书 '{}' 不存在", id)))?;

    let domains = serde_json::from_str(&certificate.domains_json).map_err(ApiError::internal)?;
    let previous_remote_id = certificate.provider_remote_id.clone();
    let updated = crate::storage::LocalCertificateUpsert {
        name: certificate.name.clone(),
        domains,
        issuer: certificate.issuer.clone(),
        valid_from: certificate.valid_from,
        valid_to: certificate.valid_to,
        source_type: certificate.source_type.clone(),
        provider_remote_id: None,
        provider_remote_domains: Vec::new(),
        last_remote_fingerprint: certificate.last_remote_fingerprint.clone(),
        sync_status: "idle".to_string(),
        sync_message: match previous_remote_id.as_deref() {
            Some(remote_id) => format!("已解除与雷池证书 {} 的绑定。", remote_id),
            None => "已清除雷池证书绑定信息。".to_string(),
        },
        auto_sync_enabled: certificate.auto_sync_enabled,
        trusted: certificate.trusted,
        expired: certificate.expired,
        notes: certificate.notes.clone(),
        last_synced_at: certificate.last_synced_at,
    };

    store
        .update_local_certificate(id, &updated)
        .await
        .map_err(map_storage_write_error)?;

    Ok(Json(WriteStatusResponse {
        success: true,
        message: match previous_remote_id {
            Some(remote_id) => format!("本地证书 #{} 已解除与雷池证书 {} 的绑定。", id, remote_id),
            None => format!("本地证书 #{} 当前没有雷池绑定，已清理残留同步信息。", id),
        },
    }))
}

pub(super) async fn delete_local_certificate_handler(
    State(state): State<ApiState>,
    Path(id): Path<i64>,
) -> ApiResult<Json<WriteStatusResponse>> {
    let store = sqlite_store(&state)?;
    let http3_message = maybe_clear_http3_managed_certificate(&state, store, id).await?;
    let deleted = store
        .delete_local_certificate(id)
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
            message: match http3_message {
                Some(extra) => format!(
                    "本地证书 {} 已删除，并已立即刷新新连接的证书选择。{}",
                    id, extra
                ),
                None => format!("本地证书 {} 已删除，并已立即刷新新连接的证书选择。", id),
            },
        }))
    } else {
        Err(ApiError::not_found(format!("本地证书 '{}' 不存在", id)))
    }
}
