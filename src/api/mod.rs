mod conversions;
mod types;

use self::types::*;
use crate::config::{Config, Rule, RuleResponseBodySource, RuleResponseTemplate, RuntimeProfile};
use crate::core::WafContext;
use axum::{
    extract::Json as ExtractJson,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{delete, get, patch},
    Json, Router,
};
use serde::Deserialize;
use std::fs;
use std::io::{Cursor, Read};
use std::net::SocketAddr;
use std::path::{Component, Path as FsPath, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;
use zip::ZipArchive;

pub struct ApiServer {
    addr: SocketAddr,
    context: Arc<WafContext>,
}

#[derive(Clone)]
struct ApiState {
    context: Arc<WafContext>,
}

impl ApiServer {
    pub fn new(addr: SocketAddr, context: Arc<WafContext>) -> Self {
        Self { addr, context }
    }

    pub async fn start(self) -> anyhow::Result<()> {
        let state = ApiState {
            context: Arc::clone(&self.context),
        };
        let app = Router::new()
            .route("/health", get(health_handler))
            .route("/metrics", get(metrics_handler))
            .route(
                "/l4/config",
                get(get_l4_config_handler).put(update_l4_config_handler),
            )
            .route("/l4/stats", get(get_l4_stats_handler))
            .route(
                "/l7/config",
                get(get_l7_config_handler).put(update_l7_config_handler),
            )
            .route("/l7/stats", get(get_l7_stats_handler))
            .route(
                "/settings",
                get(get_settings_handler).put(update_settings_handler),
            )
            .route("/events", get(list_security_events_handler))
            .route("/events/:id", patch(update_security_event_handler))
            .route("/blocked-ips", get(list_blocked_ips_handler))
            .route("/blocked-ips/:id", delete(delete_blocked_ip_handler))
            .route("/rules", get(list_rules_handler).post(create_rule_handler))
            .route(
                "/rule-action-plugins",
                get(list_rule_action_plugins_handler),
            )
            .route(
                "/rule-action-plugins/install",
                axum::routing::post(install_rule_action_plugin_handler),
            )
            .route(
                "/rule-action-templates",
                get(list_rule_action_templates_handler),
            )
            .route(
                "/sites/local",
                get(list_local_sites_handler).post(create_local_site_handler),
            )
            .route(
                "/sites/local/:id",
                get(get_local_site_handler)
                    .put(update_local_site_handler)
                    .delete(delete_local_site_handler),
            )
            .route(
                "/certificates/local",
                get(list_local_certificates_handler).post(create_local_certificate_handler),
            )
            .route(
                "/certificates/local/generate",
                axum::routing::post(generate_local_certificate_handler),
            )
            .route(
                "/certificates/local/:id",
                get(get_local_certificate_handler)
                    .put(update_local_certificate_handler)
                    .delete(delete_local_certificate_handler),
            )
            .route(
                "/integrations/safeline/test",
                axum::routing::post(test_safeline_handler),
            )
            .route(
                "/integrations/safeline/sites",
                axum::routing::post(list_safeline_sites_handler),
            )
            .route(
                "/integrations/safeline/sites/cached",
                get(list_cached_safeline_sites_handler),
            )
            .route(
                "/integrations/safeline/mappings",
                get(list_safeline_mappings_handler).put(update_safeline_mappings_handler),
            )
            .route(
                "/integrations/safeline/pull/sites",
                axum::routing::post(pull_safeline_sites_handler),
            )
            .route(
                "/integrations/safeline/pull/sites/:remote_site_id",
                axum::routing::post(pull_safeline_site_handler),
            )
            .route(
                "/integrations/safeline/push/sites",
                axum::routing::post(push_safeline_sites_handler),
            )
            .route(
                "/integrations/safeline/push/sites/:local_site_id",
                axum::routing::post(push_safeline_site_handler),
            )
            .route(
                "/integrations/safeline/site-links",
                get(list_site_sync_links_handler).put(upsert_site_sync_link_handler),
            )
            .route(
                "/integrations/safeline/site-links/:id",
                delete(delete_site_sync_link_handler),
            )
            .route(
                "/integrations/safeline/sync/events",
                axum::routing::post(sync_safeline_events_handler),
            )
            .route(
                "/integrations/safeline/sync/state",
                get(get_safeline_sync_state_handler),
            )
            .route(
                "/integrations/safeline/sync/blocked-ips",
                axum::routing::post(sync_safeline_blocked_ips_handler),
            )
            .route(
                "/integrations/safeline/pull/blocked-ips",
                axum::routing::post(pull_safeline_blocked_ips_handler),
            )
            .route(
                "/rules/:id",
                get(get_rule_handler)
                    .put(update_rule_handler)
                    .delete(delete_rule_handler),
            )
            .with_state(state);

        let listener = TcpListener::bind(self.addr).await?;
        log::info!("API server listening on {}", self.addr);

        axum::serve(listener, app).await?;
        Ok(())
    }
}

async fn health_handler(State(state): State<ApiState>) -> Json<HealthResponse> {
    let upstream = state.context.upstream_health_snapshot();
    Json(HealthResponse {
        status: if upstream.healthy {
            "healthy".to_string()
        } else {
            "degraded".to_string()
        },
        version: env!("CARGO_PKG_VERSION").to_string(),
        upstream_healthy: upstream.healthy,
        upstream_last_check_at: upstream.last_check_at,
        upstream_last_error: upstream.last_error,
    })
}

async fn metrics_handler(State(state): State<ApiState>) -> Json<MetricsResponse> {
    let metrics = state.context.metrics_snapshot();
    let storage_summary = if let Some(store) = state.context.sqlite_store.as_ref() {
        match store.metrics_summary().await {
            Ok(summary) => Some(summary),
            Err(err) => {
                log::warn!("Failed to query SQLite metrics summary: {}", err);
                None
            }
        }
    } else {
        None
    };

    Json(build_metrics_response(
        metrics,
        state.context.active_rule_count(),
        storage_summary,
    ))
}

async fn get_settings_handler(State(state): State<ApiState>) -> ApiResult<Json<SettingsResponse>> {
    let config = persisted_config(&state).await?;
    Ok(Json(SettingsResponse::from_config(&config)))
}

async fn get_l4_config_handler(State(state): State<ApiState>) -> ApiResult<Json<L4ConfigResponse>> {
    let config = persisted_config(&state).await?;
    Ok(Json(L4ConfigResponse::from_config(
        &config,
        state.context.l4_inspector.is_some(),
    )))
}

async fn get_l7_config_handler(State(state): State<ApiState>) -> ApiResult<Json<L7ConfigResponse>> {
    let config = persisted_config(&state).await?;
    Ok(Json(L7ConfigResponse::from_config(
        &config,
        state.context.l7_inspector.is_some(),
    )))
}

async fn update_l4_config_handler(
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

async fn update_l7_config_handler(
    State(state): State<ApiState>,
    ExtractJson(payload): ExtractJson<L7ConfigUpdateRequest>,
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

    Ok(Json(WriteStatusResponse {
        success: true,
        message: "L7 配置已写入数据库。监听、代理与协议栈相关参数需重启服务后生效。".to_string(),
    }))
}

async fn update_settings_handler(
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

async fn get_l4_stats_handler(State(state): State<ApiState>) -> ApiResult<Json<L4StatsResponse>> {
    let response = state
        .context
        .l4_inspector
        .as_ref()
        .map(|inspector| L4StatsResponse::from_stats(inspector.get_statistics()))
        .unwrap_or_else(L4StatsResponse::disabled);

    Ok(Json(response))
}

async fn get_l7_stats_handler(State(state): State<ApiState>) -> ApiResult<Json<L7StatsResponse>> {
    Ok(Json(L7StatsResponse::from_context(state.context.as_ref())))
}

async fn test_safeline_handler(
    ExtractJson(payload): ExtractJson<SafeLineTestRequest>,
) -> ApiResult<Json<SafeLineTestResponse>> {
    let result = crate::integrations::safeline::probe(&payload.into_config())
        .await
        .map_err(|err| ApiError::bad_request(err.to_string()))?;

    Ok(Json(SafeLineTestResponse::from(result)))
}

async fn list_safeline_sites_handler(
    State(state): State<ApiState>,
    ExtractJson(payload): ExtractJson<SafeLineTestRequest>,
) -> ApiResult<Json<SafeLineSitesResponse>> {
    let sites = crate::integrations::safeline::list_sites(&payload.into_config())
        .await
        .map_err(|err| ApiError::bad_request(err.to_string()))?;
    let cached_at = if let Some(store) = state.context.sqlite_store.as_deref() {
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
        .flatten()
    } else {
        None
    };

    Ok(Json(SafeLineSitesResponse {
        total: sites.len() as u32,
        cached_at,
        sites: sites.into_iter().map(SafeLineSiteResponse::from).collect(),
    }))
}

async fn list_cached_safeline_sites_handler(
    State(state): State<ApiState>,
) -> ApiResult<Json<SafeLineSitesResponse>> {
    let Some(store) = state.context.sqlite_store.as_deref() else {
        return Ok(Json(SafeLineSitesResponse {
            total: 0,
            cached_at: None,
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
        sites,
    }))
}

async fn list_safeline_mappings_handler(
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

async fn update_safeline_mappings_handler(
    State(state): State<ApiState>,
    ExtractJson(payload): ExtractJson<SafeLineMappingsUpdateRequest>,
) -> ApiResult<Json<WriteStatusResponse>> {
    let store = sqlite_store(&state)?;
    let mappings = payload
        .into_storage_mappings()
        .map_err(ApiError::bad_request)?;
    store
        .replace_safeline_site_mappings(&mappings)
        .await
        .map_err(ApiError::internal)?;

    Ok(Json(WriteStatusResponse {
        success: true,
        message: "雷池站点映射已写入数据库。".to_string(),
    }))
}

async fn list_local_sites_handler(
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

async fn get_local_site_handler(
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

async fn create_local_site_handler(
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

    Ok((
        StatusCode::CREATED,
        Json(LocalSiteResponse::try_from(created).map_err(ApiError::internal)?),
    ))
}

async fn update_local_site_handler(
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
        Ok(Json(WriteStatusResponse {
            success: true,
            message: format!("本地站点 {} 已更新。重启服务后生效。", id),
        }))
    } else {
        Err(ApiError::not_found(format!("本地站点 '{}' 不存在", id)))
    }
}

async fn delete_local_site_handler(
    State(state): State<ApiState>,
    Path(id): Path<i64>,
) -> ApiResult<Json<WriteStatusResponse>> {
    let store = sqlite_store(&state)?;
    let deleted = store
        .delete_local_site(id)
        .await
        .map_err(ApiError::internal)?;

    if deleted {
        Ok(Json(WriteStatusResponse {
            success: true,
            message: format!("本地站点 {} 已删除。重启服务后生效。", id),
        }))
    } else {
        Err(ApiError::not_found(format!("本地站点 '{}' 不存在", id)))
    }
}

async fn list_local_certificates_handler(
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

async fn get_local_certificate_handler(
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

async fn create_local_certificate_handler(
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

    Ok((
        StatusCode::CREATED,
        Json(LocalCertificateResponse::try_from(created).map_err(ApiError::internal)?),
    ))
}

async fn generate_local_certificate_handler(
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

    Ok((
        StatusCode::CREATED,
        Json(LocalCertificateResponse::try_from(created).map_err(ApiError::internal)?),
    ))
}

async fn update_local_certificate_handler(
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
        Ok(Json(WriteStatusResponse {
            success: true,
            message: format!("本地证书 {} 已更新。重启服务后生效。", id),
        }))
    } else {
        Err(ApiError::not_found(format!("本地证书 '{}' 不存在", id)))
    }
}

async fn delete_local_certificate_handler(
    State(state): State<ApiState>,
    Path(id): Path<i64>,
) -> ApiResult<Json<WriteStatusResponse>> {
    let store = sqlite_store(&state)?;
    let deleted = store
        .delete_local_certificate(id)
        .await
        .map_err(ApiError::internal)?;

    if deleted {
        Ok(Json(WriteStatusResponse {
            success: true,
            message: format!("本地证书 {} 已删除。重启服务后生效。", id),
        }))
    } else {
        Err(ApiError::not_found(format!("本地证书 '{}' 不存在", id)))
    }
}

async fn list_site_sync_links_handler(
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

async fn upsert_site_sync_link_handler(
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

async fn delete_site_sync_link_handler(
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

async fn pull_safeline_sites_handler(
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
            "雷池站点回流完成，新增站点 {} 个、更新站点 {} 个，新增证书 {} 个、更新证书 {} 个。",
            result.imported_sites,
            result.updated_sites,
            result.imported_certificates,
            result.updated_certificates
        ),
    }))
}

async fn pull_safeline_site_handler(
    State(state): State<ApiState>,
    Path(remote_site_id): Path<String>,
) -> ApiResult<Json<WriteStatusResponse>> {
    let store = sqlite_store(&state)?;
    let config = persisted_config(&state).await?;
    let safeline = &config.integrations.safeline;

    if !safeline.enabled {
        return Err(ApiError::conflict("雷池集成尚未启用".to_string()));
    }

    let result = crate::integrations::safeline_sync::pull_site(store, safeline, &remote_site_id)
        .await
        .map_err(|err| ApiError::bad_request(err.to_string()))?;

    Ok(Json(WriteStatusResponse {
        success: true,
        message: match result.action {
            crate::integrations::safeline_sync::SingleSiteSyncAction::Created => format!(
                "雷池站点 {} 已导入到本地站点 #{}。",
                result.remote_site_id, result.local_site_id
            ),
            crate::integrations::safeline_sync::SingleSiteSyncAction::Updated => format!(
                "雷池站点 {} 已回流更新到本地站点 #{}。",
                result.remote_site_id, result.local_site_id
            ),
        },
    }))
}

async fn push_safeline_sites_handler(
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

async fn push_safeline_site_handler(
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

async fn sync_safeline_events_handler(
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

async fn get_safeline_sync_state_handler(
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

async fn sync_safeline_blocked_ips_handler(
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

async fn pull_safeline_blocked_ips_handler(
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

async fn list_security_events_handler(
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

async fn update_security_event_handler(
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

async fn list_blocked_ips_handler(
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

async fn list_rules_handler(State(state): State<ApiState>) -> ApiResult<Json<RulesListResponse>> {
    let store = rules_store(&state)?;
    let rules = store.load_rules().await.map_err(ApiError::internal)?;

    Ok(Json(RulesListResponse {
        rules: rules.into_iter().map(RuleResponse::from).collect(),
    }))
}

async fn get_rule_handler(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> ApiResult<Json<RuleResponse>> {
    let store = rules_store(&state)?;
    let rule = store.load_rule(&id).await.map_err(ApiError::internal)?;

    match rule {
        Some(rule) => Ok(Json(RuleResponse::from(rule))),
        None => Err(ApiError::not_found(format!("Rule '{}' not found", id))),
    }
}

async fn create_rule_handler(
    State(state): State<ApiState>,
    ExtractJson(payload): ExtractJson<RuleUpsertRequest>,
) -> ApiResult<(StatusCode, Json<WriteStatusResponse>)> {
    let store = rules_store(&state)?;
    let rule = payload.into_rule().map_err(ApiError::bad_request)?;
    crate::rules::validate_rule(&rule).map_err(|err| ApiError::bad_request(err.to_string()))?;
    let inserted = store.insert_rule(&rule).await.map_err(ApiError::internal)?;

    if inserted {
        Ok((
            StatusCode::CREATED,
            Json(WriteStatusResponse {
                success: true,
                message: format!("Rule '{}' created", rule.id),
            }),
        ))
    } else {
        Err(ApiError::conflict(format!(
            "Rule '{}' already exists",
            rule.id
        )))
    }
}

async fn list_rule_action_plugins_handler(
    State(state): State<ApiState>,
) -> ApiResult<Json<RuleActionPluginsResponse>> {
    let store = sqlite_store(&state)?;
    let plugins = store
        .list_rule_action_plugins()
        .await
        .map_err(ApiError::internal)?;
    let plugins: Vec<_> = plugins.into_iter().map(Into::into).collect();

    Ok(Json(RuleActionPluginsResponse {
        total: plugins.len() as u32,
        plugins,
    }))
}

async fn list_rule_action_templates_handler(
    State(state): State<ApiState>,
) -> ApiResult<Json<RuleActionTemplatesResponse>> {
    let store = sqlite_store(&state)?;
    let templates = store
        .list_rule_action_templates()
        .await
        .map_err(ApiError::internal)?;
    let templates: Result<Vec<_>, _> = templates
        .into_iter()
        .map(RuleActionTemplateResponse::try_from)
        .collect();
    let templates = templates.map_err(ApiError::internal)?;

    Ok(Json(RuleActionTemplatesResponse {
        total: templates.len() as u32,
        templates,
    }))
}

async fn install_rule_action_plugin_handler(
    State(state): State<ApiState>,
    ExtractJson(payload): ExtractJson<InstallRuleActionPluginRequest>,
) -> ApiResult<(StatusCode, Json<WriteStatusResponse>)> {
    let store = sqlite_store(&state)?;
    install_rule_action_plugin_from_url(store, &payload.package_url)
        .await
        .map_err(ApiError::bad_request)?;

    Ok((
        StatusCode::CREATED,
        Json(WriteStatusResponse {
            success: true,
            message: "规则模板插件已安装".to_string(),
        }),
    ))
}

async fn update_rule_handler(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    ExtractJson(payload): ExtractJson<RuleUpsertRequest>,
) -> ApiResult<Json<WriteStatusResponse>> {
    let store = rules_store(&state)?;
    let rule = payload
        .into_rule_with_id(id)
        .map_err(ApiError::bad_request)?;
    crate::rules::validate_rule(&rule).map_err(|err| ApiError::bad_request(err.to_string()))?;
    store.upsert_rule(&rule).await.map_err(ApiError::internal)?;

    Ok(Json(WriteStatusResponse {
        success: true,
        message: format!("Rule '{}' updated", rule.id),
    }))
}

async fn delete_rule_handler(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> ApiResult<Json<WriteStatusResponse>> {
    let store = rules_store(&state)?;
    let deleted = store.delete_rule(&id).await.map_err(ApiError::internal)?;

    if deleted {
        Ok(Json(WriteStatusResponse {
            success: true,
            message: format!("Rule '{}' deleted", id),
        }))
    } else {
        Err(ApiError::not_found(format!("Rule '{}' not found", id)))
    }
}

async fn delete_blocked_ip_handler(
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
                    .l4_inspector
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

fn build_metrics_response(
    metrics: Option<crate::metrics::MetricsSnapshot>,
    active_rules: u64,
    storage_summary: Option<crate::storage::StorageMetricsSummary>,
) -> MetricsResponse {
    let snapshot = metrics.unwrap_or(crate::metrics::MetricsSnapshot {
        total_packets: 0,
        blocked_packets: 0,
        blocked_l4: 0,
        blocked_l7: 0,
        total_bytes: 0,
        proxied_requests: 0,
        proxy_successes: 0,
        proxy_failures: 0,
        proxy_fail_close_rejections: 0,
        upstream_healthcheck_successes: 0,
        upstream_healthcheck_failures: 0,
        proxy_latency_micros_total: 0,
        average_proxy_latency_micros: 0,
    });
    let sqlite_enabled = storage_summary.is_some();
    let storage_summary = storage_summary.unwrap_or_default();

    MetricsResponse {
        total_packets: snapshot.total_packets,
        blocked_packets: snapshot.blocked_packets,
        blocked_l4: snapshot.blocked_l4,
        blocked_l7: snapshot.blocked_l7,
        total_bytes: snapshot.total_bytes,
        proxied_requests: snapshot.proxied_requests,
        proxy_successes: snapshot.proxy_successes,
        proxy_failures: snapshot.proxy_failures,
        proxy_fail_close_rejections: snapshot.proxy_fail_close_rejections,
        upstream_healthcheck_successes: snapshot.upstream_healthcheck_successes,
        upstream_healthcheck_failures: snapshot.upstream_healthcheck_failures,
        proxy_latency_micros_total: snapshot.proxy_latency_micros_total,
        average_proxy_latency_micros: snapshot.average_proxy_latency_micros,
        active_rules,
        sqlite_enabled,
        persisted_security_events: storage_summary.security_events,
        persisted_blocked_ips: storage_summary.blocked_ips,
        persisted_rules: storage_summary.rules,
        last_persisted_event_at: storage_summary.latest_event_at,
        last_rule_update_at: storage_summary.latest_rule_update_at,
    }
}

#[derive(Debug, Deserialize)]
struct RuleActionPluginManifest {
    plugin_id: String,
    name: String,
    version: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    templates: Vec<RuleActionPluginTemplateManifest>,
}

#[derive(Debug, Deserialize)]
struct RuleActionPluginTemplateManifest {
    id: String,
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default = "default_rule_layer_l7")]
    layer: String,
    #[serde(default = "default_rule_action_respond")]
    action: String,
    #[serde(default)]
    pattern: String,
    #[serde(default = "default_rule_severity_high")]
    severity: String,
    response_template: RuleResponseTemplatePayload,
}

async fn install_rule_action_plugin_from_url(
    store: &crate::storage::SqliteStore,
    package_url: &str,
) -> Result<(), String> {
    let package_url = package_url.trim();
    if package_url.is_empty() {
        return Err("package_url 不能为空".to_string());
    }
    let response = reqwest::Client::new()
        .get(package_url)
        .send()
        .await
        .map_err(|err| format!("下载插件包失败: {}", err))?;
    if !response.status().is_success() {
        return Err(format!("下载插件包失败: HTTP {}", response.status()));
    }
    let bytes = response
        .bytes()
        .await
        .map_err(|err| format!("读取插件包失败: {}", err))?;
    install_rule_action_plugin_from_bytes(store, bytes.as_ref()).await
}

async fn install_rule_action_plugin_from_bytes(
    store: &crate::storage::SqliteStore,
    bytes: &[u8],
) -> Result<(), String> {
    let mut archive =
        ZipArchive::new(Cursor::new(bytes)).map_err(|err| format!("解析插件 zip 失败: {}", err))?;
    let manifest = read_rule_action_plugin_manifest(&mut archive)?;
    validate_rule_action_plugin_manifest(&manifest)?;

    let plugin_assets_dir = PathBuf::from(crate::rules::RULE_RESPONSE_FILES_DIR)
        .join("plugins")
        .join(&manifest.plugin_id);
    if plugin_assets_dir.exists() {
        fs::remove_dir_all(&plugin_assets_dir)
            .map_err(|err| format!("清理旧插件资源失败: {}", err))?;
    }
    fs::create_dir_all(&plugin_assets_dir).map_err(|err| format!("创建插件目录失败: {}", err))?;

    let mut templates = Vec::with_capacity(manifest.templates.len());
    for template in &manifest.templates {
        let mut response_template: RuleResponseTemplate = template.response_template.clone().into();
        if matches!(response_template.body_source, RuleResponseBodySource::File) {
            let relative_asset_path =
                sanitize_relative_plugin_path(&response_template.body_file_path)?;
            let zip_entry_path = format!("responses/{}", relative_asset_path.display());
            extract_plugin_asset(
                &mut archive,
                &zip_entry_path,
                &plugin_assets_dir.join(&relative_asset_path),
            )?;
            response_template.body_file_path = format!(
                "plugins/{}/{}",
                manifest.plugin_id,
                relative_asset_path.to_string_lossy()
            );
        }

        let rule = Rule {
            id: format!("plugin:{}:{}", manifest.plugin_id, template.id),
            name: template.name.clone(),
            enabled: true,
            layer: crate::config::RuleLayer::parse(&template.layer)
                .map_err(|err| err.to_string())?,
            pattern: template.pattern.clone(),
            action: crate::config::RuleAction::parse(&template.action)
                .map_err(|err| err.to_string())?,
            severity: crate::config::Severity::parse(&template.severity)
                .map_err(|err| err.to_string())?,
            plugin_template_id: Some(format!("{}:{}", manifest.plugin_id, template.id)),
            response_template: Some(response_template.clone()),
        };
        crate::rules::validate_rule(&rule).map_err(|err| err.to_string())?;

        templates.push(crate::storage::RuleActionTemplateUpsert {
            template_id: format!("{}:{}", manifest.plugin_id, template.id),
            plugin_id: manifest.plugin_id.clone(),
            name: template.name.clone(),
            description: template.description.clone(),
            layer: template.layer.clone(),
            action: template.action.clone(),
            pattern: template.pattern.clone(),
            severity: template.severity.clone(),
            response_template,
        });
    }

    store
        .upsert_rule_action_plugin(&crate::storage::RuleActionPluginUpsert {
            plugin_id: manifest.plugin_id.clone(),
            name: manifest.name.clone(),
            version: manifest.version.clone(),
            description: manifest.description.clone(),
        })
        .await
        .map_err(|err| err.to_string())?;
    store
        .replace_rule_action_templates(&manifest.plugin_id, &templates)
        .await
        .map_err(|err| err.to_string())?;

    Ok(())
}

fn read_rule_action_plugin_manifest(
    archive: &mut ZipArchive<Cursor<&[u8]>>,
) -> Result<RuleActionPluginManifest, String> {
    let mut manifest_file = archive
        .by_name("manifest.json")
        .map_err(|_| "插件包缺少 manifest.json".to_string())?;
    let mut manifest_json = String::new();
    manifest_file
        .read_to_string(&mut manifest_json)
        .map_err(|err| format!("读取 manifest.json 失败: {}", err))?;
    serde_json::from_str::<RuleActionPluginManifest>(&manifest_json)
        .map_err(|err| format!("解析 manifest.json 失败: {}", err))
}

fn validate_rule_action_plugin_manifest(manifest: &RuleActionPluginManifest) -> Result<(), String> {
    if manifest.plugin_id.trim().is_empty() {
        return Err("plugin_id 不能为空".to_string());
    }
    if manifest.name.trim().is_empty() {
        return Err("插件名称不能为空".to_string());
    }
    if manifest.version.trim().is_empty() {
        return Err("插件版本不能为空".to_string());
    }
    if manifest.templates.is_empty() {
        return Err("插件包至少需要一个模板".to_string());
    }
    for template in &manifest.templates {
        if template.id.trim().is_empty() {
            return Err("模板 id 不能为空".to_string());
        }
        if template.name.trim().is_empty() {
            return Err("模板名称不能为空".to_string());
        }
    }
    Ok(())
}

fn sanitize_relative_plugin_path(value: &str) -> Result<PathBuf, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err("文件模板的 body_file_path 不能为空".to_string());
    }
    let path = FsPath::new(trimmed);
    if path.is_absolute() {
        return Err("插件内文件路径必须使用相对路径".to_string());
    }
    for component in path.components() {
        if matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        ) {
            return Err("插件内文件路径不能包含越界路径".to_string());
        }
    }
    Ok(path.to_path_buf())
}

fn extract_plugin_asset(
    archive: &mut ZipArchive<Cursor<&[u8]>>,
    zip_entry_path: &str,
    output_path: &PathBuf,
) -> Result<(), String> {
    let mut file = archive
        .by_name(zip_entry_path)
        .map_err(|_| format!("插件包缺少资源文件 '{}'", zip_entry_path))?;
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent).map_err(|err| format!("创建插件资源目录失败: {}", err))?;
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|err| format!("读取插件资源失败: {}", err))?;
    fs::write(output_path, bytes).map_err(|err| format!("写入插件资源失败: {}", err))
}

fn default_rule_layer_l7() -> String {
    "l7".to_string()
}

fn default_rule_action_respond() -> String {
    "respond".to_string()
}

fn default_rule_severity_high() -> String {
    "high".to_string()
}

pub(super) fn parse_sort_direction(
    value: Option<&str>,
) -> Result<crate::storage::SortDirection, String> {
    match value.unwrap_or("desc").trim().to_ascii_lowercase().as_str() {
        "asc" => Ok(crate::storage::SortDirection::Asc),
        "desc" => Ok(crate::storage::SortDirection::Desc),
        other => Err(format!("Unsupported sort_direction '{}'", other)),
    }
}

pub(super) fn parse_event_sort_field(
    value: Option<&str>,
) -> Result<crate::storage::EventSortField, String> {
    match value
        .unwrap_or("created_at")
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "created_at" => Ok(crate::storage::EventSortField::CreatedAt),
        "source_ip" => Ok(crate::storage::EventSortField::SourceIp),
        "dest_port" => Ok(crate::storage::EventSortField::DestPort),
        other => Err(format!("Unsupported event sort_by '{}'", other)),
    }
}

pub(super) fn parse_blocked_ip_sort_field(
    value: Option<&str>,
) -> Result<crate::storage::BlockedIpSortField, String> {
    match value
        .unwrap_or("blocked_at")
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "blocked_at" => Ok(crate::storage::BlockedIpSortField::BlockedAt),
        "expires_at" => Ok(crate::storage::BlockedIpSortField::ExpiresAt),
        "ip" => Ok(crate::storage::BlockedIpSortField::Ip),
        other => Err(format!("Unsupported blocked IP sort_by '{}'", other)),
    }
}

fn sqlite_store(state: &ApiState) -> ApiResult<&crate::storage::SqliteStore> {
    if !state.context.config.sqlite_enabled {
        return Err(ApiError::conflict(
            "SQLite storage is disabled in configuration".to_string(),
        ));
    }

    state
        .context
        .sqlite_store
        .as_deref()
        .ok_or_else(|| ApiError::conflict("SQLite store is unavailable".to_string()))
}

fn rules_store(state: &ApiState) -> ApiResult<&crate::storage::SqliteStore> {
    let store = sqlite_store(state)?;
    if !state.context.config.sqlite_rules_enabled {
        return Err(ApiError::conflict(
            "SQLite-backed rules are disabled in configuration".to_string(),
        ));
    }
    Ok(store)
}

async fn persisted_config(state: &ApiState) -> ApiResult<Config> {
    let store = sqlite_store(state)?;
    store
        .load_app_config()
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::conflict("数据库中未找到系统配置".to_string()))
}

pub(super) fn non_empty_string(value: String) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

pub(super) fn unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

pub(super) fn runtime_profile_label(profile: RuntimeProfile) -> &'static str {
    match profile {
        RuntimeProfile::Minimal => "minimal",
        RuntimeProfile::Standard => "standard",
    }
}

fn map_storage_write_error(error: anyhow::Error) -> ApiError {
    if let Some(sqlx_error) = error.downcast_ref::<sqlx::Error>() {
        if let Some(database_error) = sqlx_error.as_database_error() {
            if database_error.is_unique_violation() {
                return ApiError::conflict(database_error.message().to_string());
            }
            if database_error.is_foreign_key_violation() {
                return ApiError::bad_request(database_error.message().to_string());
            }
        }
    }

    ApiError::internal(error)
}

type ApiResult<T> = Result<T, ApiError>;

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: message.into(),
        }
    }

    fn conflict(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            message: message.into(),
        }
    }

    fn internal(error: impl std::fmt::Display) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: error.to_string(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ErrorResponse {
                error: self.message,
            }),
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{RuleAction, RuleLayer, Severity};
    use crate::storage::{LocalCertificateEntry, LocalSiteEntry, SiteSyncLinkEntry, SqliteStore};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_test_db_path(name: &str) -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        std::env::temp_dir()
            .join(format!(
                "{}_api_{}_{}.db",
                env!("CARGO_PKG_NAME"),
                name,
                nanos
            ))
            .display()
            .to_string()
    }

    #[test]
    fn test_build_metrics_response_without_sources() {
        let response = build_metrics_response(None, 0, None);

        assert_eq!(response.total_packets, 0);
        assert_eq!(response.blocked_packets, 0);
        assert_eq!(response.active_rules, 0);
        assert!(!response.sqlite_enabled);
        assert_eq!(response.persisted_security_events, 0);
        assert_eq!(response.persisted_blocked_ips, 0);
        assert_eq!(response.persisted_rules, 0);
        assert!(response.last_persisted_event_at.is_none());
        assert!(response.last_rule_update_at.is_none());
    }

    #[test]
    fn test_build_metrics_response_with_sources() {
        let response = build_metrics_response(
            Some(crate::metrics::MetricsSnapshot {
                total_packets: 12,
                blocked_packets: 3,
                blocked_l4: 1,
                blocked_l7: 2,
                total_bytes: 1024,
                proxied_requests: 10,
                proxy_successes: 8,
                proxy_failures: 2,
                proxy_fail_close_rejections: 1,
                upstream_healthcheck_successes: 5,
                upstream_healthcheck_failures: 1,
                proxy_latency_micros_total: 40_000,
                average_proxy_latency_micros: 5_000,
            }),
            4,
            Some(crate::storage::StorageMetricsSummary {
                security_events: 7,
                blocked_ips: 2,
                latest_event_at: Some(1234567890),
                rules: 5,
                latest_rule_update_at: Some(1234567899),
            }),
        );

        assert_eq!(response.total_packets, 12);
        assert_eq!(response.blocked_packets, 3);
        assert_eq!(response.blocked_l4, 1);
        assert_eq!(response.blocked_l7, 2);
        assert_eq!(response.total_bytes, 1024);
        assert_eq!(response.proxied_requests, 10);
        assert_eq!(response.proxy_successes, 8);
        assert_eq!(response.proxy_failures, 2);
        assert_eq!(response.proxy_fail_close_rejections, 1);
        assert_eq!(response.upstream_healthcheck_successes, 5);
        assert_eq!(response.upstream_healthcheck_failures, 1);
        assert_eq!(response.proxy_latency_micros_total, 40_000);
        assert_eq!(response.average_proxy_latency_micros, 5_000);
        assert_eq!(response.active_rules, 4);
        assert!(response.sqlite_enabled);
        assert_eq!(response.persisted_security_events, 7);
        assert_eq!(response.persisted_blocked_ips, 2);
        assert_eq!(response.persisted_rules, 5);
        assert_eq!(response.last_persisted_event_at, Some(1234567890));
        assert_eq!(response.last_rule_update_at, Some(1234567899));
    }

    #[test]
    fn test_rule_response_from_rule() {
        let response = RuleResponse::from(Rule {
            id: "rule-2".to_string(),
            name: "Alert Probe".to_string(),
            enabled: false,
            layer: RuleLayer::L4,
            pattern: "probe".to_string(),
            action: RuleAction::Alert,
            severity: Severity::Medium,
            plugin_template_id: None,
            response_template: None,
        });

        assert_eq!(response.id, "rule-2");
        assert_eq!(response.layer, "l4");
        assert_eq!(response.action, "alert");
        assert_eq!(response.severity, "medium");
    }

    #[test]
    fn test_events_query_params_into_query() {
        let query = EventsQueryParams {
            limit: Some(25),
            offset: Some(10),
            layer: Some("L7".to_string()),
            provider: Some("safeline".to_string()),
            provider_site_id: Some("site-1".to_string()),
            source_ip: Some("10.0.0.1".to_string()),
            action: Some("block".to_string()),
            blocked_only: Some(true),
            handled_only: Some(true),
            created_from: Some(100),
            created_to: Some(200),
            sort_by: Some("source_ip".to_string()),
            sort_direction: Some("asc".to_string()),
        }
        .into_query();

        let query = query.unwrap();
        assert_eq!(query.limit, 25);
        assert_eq!(query.offset, 10);
        assert_eq!(query.layer.as_deref(), Some("L7"));
        assert_eq!(query.provider.as_deref(), Some("safeline"));
        assert_eq!(query.provider_site_id.as_deref(), Some("site-1"));
        assert_eq!(query.source_ip.as_deref(), Some("10.0.0.1"));
        assert_eq!(query.action.as_deref(), Some("block"));
        assert!(query.blocked_only);
        assert_eq!(query.created_from, Some(100));
        assert_eq!(query.created_to, Some(200));
        assert!(matches!(
            query.sort_by,
            crate::storage::EventSortField::SourceIp
        ));
        assert!(matches!(
            query.sort_direction,
            crate::storage::SortDirection::Asc
        ));
    }

    #[test]
    fn test_blocked_ips_query_params_into_query() {
        let query = BlockedIpsQueryParams {
            limit: Some(5),
            offset: Some(2),
            source_scope: Some("local".to_string()),
            provider: Some("safeline".to_string()),
            ip: Some("10.0.0.2".to_string()),
            keyword: Some(" rate ".to_string()),
            active_only: Some(true),
            blocked_from: Some(300),
            blocked_to: Some(400),
            sort_by: Some("ip".to_string()),
            sort_direction: Some("asc".to_string()),
        }
        .into_query();

        let query = query.unwrap();
        assert_eq!(query.limit, 5);
        assert_eq!(query.offset, 2);
        assert!(matches!(
            query.source_scope,
            crate::storage::BlockedIpSourceScope::Local
        ));
        assert_eq!(query.provider.as_deref(), Some("safeline"));
        assert_eq!(query.ip.as_deref(), Some("10.0.0.2"));
        assert_eq!(query.keyword.as_deref(), Some("rate"));
        assert!(query.active_only);
        assert_eq!(query.blocked_from, Some(300));
        assert_eq!(query.blocked_to, Some(400));
        assert!(matches!(
            query.sort_by,
            crate::storage::BlockedIpSortField::Ip
        ));
    }

    #[test]
    fn test_blocked_ips_query_keyword_empty_becomes_none() {
        let query = BlockedIpsQueryParams {
            keyword: Some("   ".to_string()),
            ..BlockedIpsQueryParams::default()
        }
        .into_query()
        .unwrap();

        assert_eq!(query.keyword, None);
    }

    #[test]
    fn test_invalid_sort_params_fail_validation() {
        let invalid_events = EventsQueryParams {
            sort_by: Some("unknown".to_string()),
            ..EventsQueryParams::default()
        }
        .into_query();
        assert!(invalid_events.is_err());

        let invalid_blocked = BlockedIpsQueryParams {
            source_scope: Some("sideways".to_string()),
            ..BlockedIpsQueryParams::default()
        }
        .into_query();
        assert!(invalid_blocked.is_err());

        let invalid_blocked_sort = BlockedIpsQueryParams {
            sort_direction: Some("sideways".to_string()),
            ..BlockedIpsQueryParams::default()
        }
        .into_query();
        assert!(invalid_blocked_sort.is_err());
    }

    #[test]
    fn test_safeline_mapping_update_rejects_duplicate_site_ids() {
        let payload = SafeLineMappingsUpdateRequest {
            mappings: vec![
                SafeLineMappingUpsertRequest {
                    safeline_site_id: "site-1".to_string(),
                    safeline_site_name: "portal".to_string(),
                    safeline_site_domain: "portal.example.com".to_string(),
                    local_alias: "门户".to_string(),
                    enabled: true,
                    is_primary: false,
                    notes: "".to_string(),
                },
                SafeLineMappingUpsertRequest {
                    safeline_site_id: "site-1".to_string(),
                    safeline_site_name: "portal-dup".to_string(),
                    safeline_site_domain: "portal-dup.example.com".to_string(),
                    local_alias: "门户副本".to_string(),
                    enabled: true,
                    is_primary: false,
                    notes: "".to_string(),
                },
            ],
        };

        let error = payload.into_storage_mappings().unwrap_err();
        assert!(error.contains("重复映射"));
    }

    #[test]
    fn test_safeline_mapping_update_rejects_disabled_primary() {
        let payload = SafeLineMappingsUpdateRequest {
            mappings: vec![SafeLineMappingUpsertRequest {
                safeline_site_id: "site-1".to_string(),
                safeline_site_name: "portal".to_string(),
                safeline_site_domain: "portal.example.com".to_string(),
                local_alias: "门户".to_string(),
                enabled: false,
                is_primary: true,
                notes: "".to_string(),
            }],
        };

        let error = payload.into_storage_mappings().unwrap_err();
        assert!(error.contains("必须保持启用状态"));
    }

    #[tokio::test]
    async fn test_local_site_request_normalizes_primary_hostname() {
        let path = unique_test_db_path("local_site_request");
        let store = SqliteStore::new(path, true).await.unwrap();

        let site = LocalSiteUpsertRequest {
            name: " Portal ".to_string(),
            primary_hostname: " portal.example.com ".to_string(),
            hostnames: vec!["www.portal.example.com".to_string()],
            listen_ports: vec![" 443 ".to_string(), "443".to_string()],
            upstreams: vec![
                " http://127.0.0.1:8080 ".to_string(),
                "http://127.0.0.1:8080".to_string(),
            ],
            enabled: true,
            tls_enabled: true,
            local_certificate_id: None,
            source: " ".to_string(),
            sync_mode: " ".to_string(),
            notes: " prod ".to_string(),
            last_synced_at: Some(123),
        }
        .into_storage_site(&store)
        .await
        .unwrap();

        assert_eq!(site.name, "Portal");
        assert_eq!(site.primary_hostname, "portal.example.com");
        assert_eq!(
            site.hostnames,
            vec![
                "portal.example.com".to_string(),
                "www.portal.example.com".to_string()
            ]
        );
        assert_eq!(site.listen_ports, vec!["443".to_string()]);
        assert_eq!(site.upstreams, vec!["http://127.0.0.1:8080".to_string()]);
        assert_eq!(site.source, "manual");
        assert_eq!(site.sync_mode, "manual");
        assert_eq!(site.notes, "prod");
    }

    #[tokio::test]
    async fn test_local_site_request_rejects_missing_certificate_reference() {
        let path = unique_test_db_path("local_site_missing_cert");
        let store = SqliteStore::new(path, true).await.unwrap();

        let error = LocalSiteUpsertRequest {
            name: "Portal".to_string(),
            primary_hostname: "portal.example.com".to_string(),
            hostnames: Vec::new(),
            listen_ports: Vec::new(),
            upstreams: Vec::new(),
            enabled: true,
            tls_enabled: true,
            local_certificate_id: Some(999),
            source: "manual".to_string(),
            sync_mode: "manual".to_string(),
            notes: String::new(),
            last_synced_at: None,
        }
        .into_storage_site(&store)
        .await
        .unwrap_err();

        assert!(error.contains("本地证书"));
    }

    #[test]
    fn test_local_certificate_request_validates_time_range() {
        let error = LocalCertificateUpsertRequest {
            name: "portal cert".to_string(),
            domains: vec!["portal.example.com".to_string()],
            issuer: "Acme".to_string(),
            valid_from: Some(200),
            valid_to: Some(100),
            source_type: "manual".to_string(),
            provider_remote_id: Some("31".to_string()),
            trusted: true,
            expired: false,
            notes: String::new(),
            last_synced_at: None,
            certificate_pem: None,
            private_key_pem: None,
        }
        .into_storage_certificate()
        .unwrap_err();

        assert!(error.contains("有效期结束时间"));
    }

    #[tokio::test]
    async fn test_site_sync_link_request_requires_existing_local_site() {
        let path = unique_test_db_path("site_link_missing_site");
        let store = SqliteStore::new(path, true).await.unwrap();

        let error = SiteSyncLinkUpsertRequest {
            local_site_id: 404,
            provider: "safeline".to_string(),
            remote_site_id: "site-1".to_string(),
            remote_site_name: String::new(),
            remote_cert_id: None,
            sync_mode: String::new(),
            last_local_hash: None,
            last_remote_hash: None,
            last_error: None,
            last_synced_at: None,
        }
        .into_storage_link(&store)
        .await
        .unwrap_err();

        assert!(error.contains("本地站点"));
    }

    #[test]
    fn test_local_site_response_parses_json_fields() {
        let response = LocalSiteResponse::try_from(LocalSiteEntry {
            id: 1,
            name: "Portal".to_string(),
            primary_hostname: "portal.example.com".to_string(),
            hostnames_json: r#"["portal.example.com","www.portal.example.com"]"#.to_string(),
            listen_ports_json: r#"["80","443"]"#.to_string(),
            upstreams_json: r#"["http://127.0.0.1:8080"]"#.to_string(),
            enabled: true,
            tls_enabled: true,
            local_certificate_id: Some(3),
            source: "manual".to_string(),
            sync_mode: "manual".to_string(),
            notes: String::new(),
            last_synced_at: Some(123),
            created_at: 100,
            updated_at: 200,
        })
        .unwrap();

        assert_eq!(response.hostnames.len(), 2);
        assert_eq!(response.listen_ports, vec!["80", "443"]);
        assert_eq!(response.upstreams, vec!["http://127.0.0.1:8080"]);
    }

    #[test]
    fn test_local_certificate_response_parses_json_fields() {
        let response = LocalCertificateResponse::try_from(LocalCertificateEntry {
            id: 1,
            name: "Portal".to_string(),
            domains_json: r#"["portal.example.com","api.example.com"]"#.to_string(),
            issuer: "Acme".to_string(),
            valid_from: Some(100),
            valid_to: Some(200),
            source_type: "manual".to_string(),
            provider_remote_id: Some("31".to_string()),
            trusted: true,
            expired: false,
            notes: String::new(),
            last_synced_at: Some(123),
            created_at: 100,
            updated_at: 200,
        })
        .unwrap();

        assert_eq!(
            response.domains,
            vec!["portal.example.com", "api.example.com"]
        );
        assert_eq!(response.provider_remote_id.as_deref(), Some("31"));
    }

    #[test]
    fn test_site_sync_link_response_from_storage() {
        let response = SiteSyncLinkResponse::from(SiteSyncLinkEntry {
            id: 1,
            local_site_id: 2,
            provider: "safeline".to_string(),
            remote_site_id: "site-1".to_string(),
            remote_site_name: "portal.example.com".to_string(),
            remote_cert_id: Some("31".to_string()),
            sync_mode: "bidirectional".to_string(),
            last_local_hash: Some("local".to_string()),
            last_remote_hash: Some("remote".to_string()),
            last_error: None,
            last_synced_at: Some(123),
            created_at: 100,
            updated_at: 200,
        });

        assert_eq!(response.provider, "safeline");
        assert_eq!(response.remote_site_id, "site-1");
        assert_eq!(response.remote_cert_id.as_deref(), Some("31"));
    }
}
