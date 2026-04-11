use super::*;

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
            LocalCertificateResponse::try_from(certificate).map_err(ApiError::internal)?,
        )),
        None => Err(ApiError::not_found(format!("本地证书 '{}' 不存在", id))),
    }
}

pub(super) async fn create_local_certificate_handler(
    State(state): State<ApiState>,
    ExtractJson(payload): ExtractJson<LocalCertificateUpsertRequest>,
) -> ApiResult<(StatusCode, Json<LocalCertificateResponse>)> {
    let store = sqlite_store(&state)?;
    let (certificate, secret) = payload
        .into_storage_certificate()
        .map_err(ApiError::bad_request)?;
    let id = store
        .insert_local_certificate(&certificate)
        .await
        .map_err(map_storage_write_error)?;
    if let Some(secret) = secret {
        store
            .upsert_local_certificate_secret(id, &secret.certificate_pem, &secret.private_key_pem)
            .await
            .map_err(map_storage_write_error)?;
    }
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
        Json(LocalCertificateResponse::try_from(created).map_err(ApiError::internal)?),
    ))
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
        Json(LocalCertificateResponse::try_from(created).map_err(ApiError::internal)?),
    ))
}

pub(super) async fn update_local_certificate_handler(
    State(state): State<ApiState>,
    Path(id): Path<i64>,
    ExtractJson(payload): ExtractJson<LocalCertificateUpsertRequest>,
) -> ApiResult<Json<WriteStatusResponse>> {
    let store = sqlite_store(&state)?;
    let (certificate, secret) = payload
        .into_storage_certificate()
        .map_err(ApiError::bad_request)?;
    let updated = store
        .update_local_certificate(id, &certificate)
        .await
        .map_err(map_storage_write_error)?;

    if updated {
        if let Some(secret) = secret {
            if secret.certificate_pem.is_empty() && secret.private_key_pem.is_empty() {
                store
                    .delete_local_certificate_secret(id)
                    .await
                    .map_err(ApiError::internal)?;
            } else {
                store
                    .upsert_local_certificate_secret(
                        id,
                        &secret.certificate_pem,
                        &secret.private_key_pem,
                    )
                    .await
                    .map_err(map_storage_write_error)?;
            }
        }
        state
            .context
            .refresh_gateway_runtime_from_storage()
            .await
            .map_err(ApiError::internal)?;
        Ok(Json(WriteStatusResponse {
            success: true,
            message: format!("本地证书 {} 已更新，并已立即刷新新连接的证书选择。", id),
        }))
    } else {
        Err(ApiError::not_found(format!("本地证书 '{}' 不存在", id)))
    }
}

pub(super) async fn delete_local_certificate_handler(
    State(state): State<ApiState>,
    Path(id): Path<i64>,
) -> ApiResult<Json<WriteStatusResponse>> {
    let store = sqlite_store(&state)?;
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
            message: format!("本地证书 {} 已删除，并已立即刷新新连接的证书选择。", id),
        }))
    } else {
        Err(ApiError::not_found(format!("本地证书 '{}' 不存在", id)))
    }
}
