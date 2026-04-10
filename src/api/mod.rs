use crate::config::{Config, L4Config, Rule, RuntimeProfile, SafeLineConfig};
use crate::core::WafContext;
use crate::integrations::safeline::{SafeLineProbeResult, SafeLineSiteSummary};
use axum::{
    extract::Json as ExtractJson,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{delete, get, patch},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    status: String,
    version: String,
    upstream_healthy: bool,
    upstream_last_check_at: Option<i64>,
    upstream_last_error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SettingsResponse {
    gateway_name: String,
    auto_refresh_seconds: u32,
    upstream_endpoint: String,
    api_endpoint: String,
    emergency_mode: bool,
    sqlite_persistence: bool,
    notify_by_sound: bool,
    notification_level: String,
    retain_days: u32,
    notes: String,
    safeline: SafeLineSettingsResponse,
}

#[derive(Debug, Serialize)]
pub struct L4ConfigResponse {
    ddos_protection_enabled: bool,
    advanced_ddos_enabled: bool,
    connection_rate_limit: usize,
    syn_flood_threshold: usize,
    max_tracked_ips: usize,
    max_blocked_ips: usize,
    state_ttl_secs: u64,
    bloom_filter_scale: f64,
    runtime_enabled: bool,
    bloom_enabled: bool,
    bloom_false_positive_verification: bool,
    runtime_profile: String,
}

#[derive(Debug, Serialize)]
pub struct SafeLineSettingsResponse {
    enabled: bool,
    auto_sync_events: bool,
    auto_sync_blocked_ips_push: bool,
    auto_sync_blocked_ips_pull: bool,
    auto_sync_interval_secs: u64,
    base_url: String,
    api_token: String,
    username: String,
    password: String,
    verify_tls: bool,
    openapi_doc_path: String,
    auth_probe_path: String,
    site_list_path: String,
    event_list_path: String,
    blocklist_sync_path: String,
    blocklist_delete_path: String,
    blocklist_ip_group_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct SettingsUpdateRequest {
    gateway_name: String,
    auto_refresh_seconds: u32,
    upstream_endpoint: String,
    api_endpoint: String,
    emergency_mode: bool,
    sqlite_persistence: bool,
    notify_by_sound: bool,
    notification_level: String,
    retain_days: u32,
    notes: String,
    safeline: SafeLineSettingsRequest,
}

#[derive(Debug, Deserialize)]
pub struct L4ConfigUpdateRequest {
    ddos_protection_enabled: bool,
    advanced_ddos_enabled: bool,
    connection_rate_limit: usize,
    syn_flood_threshold: usize,
    max_tracked_ips: usize,
    max_blocked_ips: usize,
    state_ttl_secs: u64,
    bloom_filter_scale: f64,
}

#[derive(Debug, Deserialize)]
pub struct SafeLineSettingsRequest {
    enabled: bool,
    auto_sync_events: bool,
    auto_sync_blocked_ips_push: bool,
    auto_sync_blocked_ips_pull: bool,
    auto_sync_interval_secs: u64,
    base_url: String,
    api_token: String,
    username: String,
    password: String,
    verify_tls: bool,
    openapi_doc_path: String,
    auth_probe_path: String,
    site_list_path: String,
    event_list_path: String,
    blocklist_sync_path: String,
    blocklist_delete_path: String,
    blocklist_ip_group_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct SafeLineTestRequest {
    base_url: String,
    api_token: String,
    username: String,
    password: String,
    verify_tls: bool,
    openapi_doc_path: String,
    auth_probe_path: String,
    site_list_path: String,
    event_list_path: String,
    blocklist_sync_path: String,
    blocklist_delete_path: String,
    blocklist_ip_group_ids: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct SafeLineTestResponse {
    status: String,
    message: String,
    openapi_doc_reachable: bool,
    openapi_doc_status: Option<u16>,
    authenticated: bool,
    auth_probe_status: Option<u16>,
}

#[derive(Debug, Serialize)]
pub struct SafeLineSitesResponse {
    total: u32,
    sites: Vec<SafeLineSiteResponse>,
}

#[derive(Debug, Serialize)]
pub struct SafeLineSiteResponse {
    id: String,
    name: String,
    domain: String,
    status: String,
    raw: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct SafeLineMappingsResponse {
    total: u32,
    mappings: Vec<SafeLineMappingResponse>,
}

#[derive(Debug, Serialize)]
pub struct SafeLineMappingResponse {
    id: i64,
    safeline_site_id: String,
    safeline_site_name: String,
    safeline_site_domain: String,
    local_alias: String,
    enabled: bool,
    is_primary: bool,
    notes: String,
    updated_at: i64,
}

#[derive(Debug, Deserialize)]
pub struct SafeLineMappingsUpdateRequest {
    mappings: Vec<SafeLineMappingUpsertRequest>,
}

#[derive(Debug, Deserialize)]
pub struct SafeLineMappingUpsertRequest {
    safeline_site_id: String,
    safeline_site_name: String,
    safeline_site_domain: String,
    local_alias: String,
    enabled: bool,
    is_primary: bool,
    notes: String,
}

#[derive(Debug, Serialize)]
pub struct SafeLineEventSyncResponse {
    success: bool,
    imported: u32,
    skipped: u32,
    last_cursor: Option<i64>,
    message: String,
}

#[derive(Debug, Serialize)]
pub struct SafeLineSyncStateResponse {
    resource: String,
    last_cursor: Option<i64>,
    last_success_at: Option<i64>,
    last_imported_count: u32,
    last_skipped_count: u32,
    updated_at: i64,
}

#[derive(Debug, Serialize)]
pub struct SafeLineSyncOverviewResponse {
    events: Option<SafeLineSyncStateResponse>,
    blocked_ips_push: Option<SafeLineSyncStateResponse>,
    blocked_ips_pull: Option<SafeLineSyncStateResponse>,
    blocked_ips_delete: Option<SafeLineSyncStateResponse>,
}

#[derive(Debug, Serialize)]
pub struct SafeLineBlocklistSyncResponse {
    success: bool,
    synced: u32,
    skipped: u32,
    failed: u32,
    last_cursor: Option<i64>,
    message: String,
}

#[derive(Debug, Serialize)]
pub struct SafeLineBlocklistPullResponse {
    success: bool,
    imported: u32,
    skipped: u32,
    last_cursor: Option<i64>,
    message: String,
}

#[derive(Debug, Serialize)]
pub struct MetricsResponse {
    total_packets: u64,
    blocked_packets: u64,
    blocked_l4: u64,
    blocked_l7: u64,
    total_bytes: u64,
    proxied_requests: u64,
    proxy_successes: u64,
    proxy_failures: u64,
    proxy_fail_close_rejections: u64,
    upstream_healthcheck_successes: u64,
    upstream_healthcheck_failures: u64,
    proxy_latency_micros_total: u64,
    average_proxy_latency_micros: u64,
    active_rules: u64,
    sqlite_enabled: bool,
    persisted_security_events: u64,
    persisted_blocked_ips: u64,
    persisted_rules: u64,
    last_persisted_event_at: Option<i64>,
    last_rule_update_at: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct L4StatsResponse {
    enabled: bool,
    connections: crate::l4::connection::ConnectionStats,
    ddos_events: u64,
    protocol_anomalies: u64,
    traffic: u64,
    defense_actions: u64,
    bloom_stats: Option<crate::l4::bloom_filter::L4BloomStats>,
    false_positive_stats: Option<crate::l4::bloom_filter::L4FalsePositiveStats>,
    per_port_stats: Vec<crate::l4::inspector::PortStats>,
}

#[derive(Debug, Serialize)]
pub struct RulesListResponse {
    rules: Vec<RuleResponse>,
}

#[derive(Debug, Serialize)]
pub struct RuleResponse {
    id: String,
    name: String,
    enabled: bool,
    layer: String,
    pattern: String,
    action: String,
    severity: String,
}

#[derive(Debug, Deserialize)]
pub struct RuleUpsertRequest {
    id: String,
    name: String,
    enabled: bool,
    layer: String,
    pattern: String,
    action: String,
    severity: String,
}

#[derive(Debug, Serialize)]
pub struct WriteStatusResponse {
    success: bool,
    message: String,
}

#[derive(Debug, Serialize)]
pub struct SecurityEventsResponse {
    total: u64,
    limit: u32,
    offset: u32,
    events: Vec<SecurityEventResponse>,
}

#[derive(Debug, Serialize)]
pub struct SecurityEventResponse {
    id: i64,
    layer: String,
    provider: Option<String>,
    provider_site_id: Option<String>,
    provider_site_name: Option<String>,
    provider_site_domain: Option<String>,
    action: String,
    reason: String,
    source_ip: String,
    dest_ip: String,
    source_port: i64,
    dest_port: i64,
    protocol: String,
    http_method: Option<String>,
    uri: Option<String>,
    http_version: Option<String>,
    created_at: i64,
    handled: bool,
    handled_at: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct EventUpdateRequest {
    handled: bool,
}

#[derive(Debug, Serialize)]
pub struct BlockedIpsResponse {
    total: u64,
    limit: u32,
    offset: u32,
    blocked_ips: Vec<BlockedIpResponse>,
}

#[derive(Debug, Serialize)]
pub struct BlockedIpResponse {
    id: i64,
    provider: Option<String>,
    provider_remote_id: Option<String>,
    ip: String,
    reason: String,
    blocked_at: i64,
    expires_at: i64,
}

#[derive(Debug, Deserialize, Default)]
pub struct EventsQueryParams {
    limit: Option<u32>,
    offset: Option<u32>,
    layer: Option<String>,
    provider: Option<String>,
    provider_site_id: Option<String>,
    source_ip: Option<String>,
    action: Option<String>,
    blocked_only: Option<bool>,
    handled_only: Option<bool>,
    created_from: Option<i64>,
    created_to: Option<i64>,
    sort_by: Option<String>,
    sort_direction: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct BlockedIpsQueryParams {
    limit: Option<u32>,
    offset: Option<u32>,
    source_scope: Option<String>,
    provider: Option<String>,
    ip: Option<String>,
    active_only: Option<bool>,
    blocked_from: Option<i64>,
    blocked_to: Option<i64>,
    sort_by: Option<String>,
    sort_direction: Option<String>,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
}

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
                "/settings",
                get(get_settings_handler).put(update_settings_handler),
            )
            .route("/events", get(list_security_events_handler))
            .route("/events/:id", patch(update_security_event_handler))
            .route("/blocked-ips", get(list_blocked_ips_handler))
            .route("/blocked-ips/:id", delete(delete_blocked_ip_handler))
            .route("/rules", get(list_rules_handler).post(create_rule_handler))
            .route(
                "/integrations/safeline/test",
                axum::routing::post(test_safeline_handler),
            )
            .route(
                "/integrations/safeline/sites",
                axum::routing::post(list_safeline_sites_handler),
            )
            .route(
                "/integrations/safeline/mappings",
                get(list_safeline_mappings_handler).put(update_safeline_mappings_handler),
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

async fn update_settings_handler(
    State(state): State<ApiState>,
    ExtractJson(payload): ExtractJson<SettingsUpdateRequest>,
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

async fn test_safeline_handler(
    ExtractJson(payload): ExtractJson<SafeLineTestRequest>,
) -> ApiResult<Json<SafeLineTestResponse>> {
    let result = crate::integrations::safeline::probe(&payload.into_config())
        .await
        .map_err(|err| ApiError::bad_request(err.to_string()))?;

    Ok(Json(SafeLineTestResponse::from(result)))
}

async fn list_safeline_sites_handler(
    ExtractJson(payload): ExtractJson<SafeLineTestRequest>,
) -> ApiResult<Json<SafeLineSitesResponse>> {
    let sites = crate::integrations::safeline::list_sites(&payload.into_config())
        .await
        .map_err(|err| ApiError::bad_request(err.to_string()))?;

    Ok(Json(SafeLineSitesResponse {
        total: sites.len() as u32,
        sites: sites.into_iter().map(SafeLineSiteResponse::from).collect(),
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

async fn update_rule_handler(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    ExtractJson(payload): ExtractJson<RuleUpsertRequest>,
) -> ApiResult<Json<WriteStatusResponse>> {
    let store = rules_store(&state)?;
    let rule = payload
        .into_rule_with_id(id)
        .map_err(ApiError::bad_request)?;
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
        Ok(Json(WriteStatusResponse {
            success: true,
            message: if entry.provider.as_deref() == Some("safeline") {
                format!("雷池封禁记录 '{}' 已完成远端解封并从本地缓存移除。", id)
            } else {
                format!("Blocked IP record '{}' removed", id)
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

impl RuleResponse {
    fn from_rule(rule: Rule) -> Self {
        Self {
            id: rule.id,
            name: rule.name,
            enabled: rule.enabled,
            layer: rule.layer.as_str().to_string(),
            pattern: rule.pattern,
            action: rule.action.as_str().to_string(),
            severity: rule.severity.as_str().to_string(),
        }
    }
}

impl SettingsResponse {
    fn from_config(config: &Config) -> Self {
        Self {
            gateway_name: config.console_settings.gateway_name.clone(),
            auto_refresh_seconds: config.console_settings.auto_refresh_seconds,
            upstream_endpoint: config.tcp_upstream_addr.clone().unwrap_or_default(),
            api_endpoint: config.api_bind.clone(),
            emergency_mode: config.console_settings.emergency_mode,
            sqlite_persistence: config.sqlite_enabled,
            notify_by_sound: config.console_settings.notify_by_sound,
            notification_level: config.console_settings.notification_level.clone(),
            retain_days: config.console_settings.retain_days,
            notes: config.console_settings.notes.clone(),
            safeline: SafeLineSettingsResponse::from_config(&config.integrations.safeline),
        }
    }
}

impl L4ConfigResponse {
    fn from_config(config: &Config, runtime_enabled: bool) -> Self {
        Self {
            ddos_protection_enabled: config.l4_config.ddos_protection_enabled,
            advanced_ddos_enabled: config.l4_config.advanced_ddos_enabled,
            connection_rate_limit: config.l4_config.connection_rate_limit,
            syn_flood_threshold: config.l4_config.syn_flood_threshold,
            max_tracked_ips: config.l4_config.max_tracked_ips,
            max_blocked_ips: config.l4_config.max_blocked_ips,
            state_ttl_secs: config.l4_config.state_ttl_secs,
            bloom_filter_scale: config.l4_config.bloom_filter_scale,
            runtime_enabled,
            bloom_enabled: config.bloom_enabled,
            bloom_false_positive_verification: config.l4_bloom_false_positive_verification,
            runtime_profile: runtime_profile_label(config.runtime_profile).to_string(),
        }
    }
}

impl SafeLineSettingsResponse {
    fn from_config(config: &SafeLineConfig) -> Self {
        Self {
            enabled: config.enabled,
            auto_sync_events: config.auto_sync_events,
            auto_sync_blocked_ips_push: config.auto_sync_blocked_ips_push,
            auto_sync_blocked_ips_pull: config.auto_sync_blocked_ips_pull,
            auto_sync_interval_secs: config.auto_sync_interval_secs,
            base_url: config.base_url.clone(),
            api_token: config.api_token.clone(),
            username: config.username.clone(),
            password: config.password.clone(),
            verify_tls: config.verify_tls,
            openapi_doc_path: config.openapi_doc_path.clone(),
            auth_probe_path: config.auth_probe_path.clone(),
            site_list_path: config.site_list_path.clone(),
            event_list_path: config.event_list_path.clone(),
            blocklist_sync_path: config.blocklist_sync_path.clone(),
            blocklist_delete_path: config.blocklist_delete_path.clone(),
            blocklist_ip_group_ids: config.blocklist_ip_group_ids.clone(),
        }
    }
}

impl L4ConfigUpdateRequest {
    fn into_config(self, mut current: Config) -> Config {
        current.l4_config = L4Config {
            ddos_protection_enabled: self.ddos_protection_enabled,
            advanced_ddos_enabled: self.advanced_ddos_enabled,
            connection_rate_limit: self.connection_rate_limit,
            syn_flood_threshold: self.syn_flood_threshold,
            max_tracked_ips: self.max_tracked_ips,
            max_blocked_ips: self.max_blocked_ips,
            state_ttl_secs: self.state_ttl_secs,
            bloom_filter_scale: self.bloom_filter_scale,
        };

        current.normalized()
    }
}

impl SettingsUpdateRequest {
    fn into_config(self, mut current: Config) -> Result<Config, String> {
        if self.gateway_name.trim().is_empty() {
            return Err("网关名称不能为空".to_string());
        }
        if self.api_endpoint.trim().is_empty() {
            return Err("控制面 API 地址不能为空".to_string());
        }

        current.console_settings.gateway_name = self.gateway_name;
        current.console_settings.auto_refresh_seconds = self.auto_refresh_seconds;
        current.tcp_upstream_addr = non_empty_string(self.upstream_endpoint);
        current.api_bind = self.api_endpoint.trim().to_string();
        current.console_settings.emergency_mode = self.emergency_mode;
        current.sqlite_enabled = self.sqlite_persistence;
        current.console_settings.notify_by_sound = self.notify_by_sound;
        current.console_settings.notification_level = self.notification_level;
        current.console_settings.retain_days = self.retain_days;
        current.console_settings.notes = self.notes;
        current.integrations.safeline = self.safeline.into_config();

        Ok(current.normalized())
    }
}

impl SafeLineSettingsRequest {
    fn into_config(self) -> SafeLineConfig {
        SafeLineConfig {
            enabled: self.enabled,
            auto_sync_events: self.auto_sync_events,
            auto_sync_blocked_ips_push: self.auto_sync_blocked_ips_push,
            auto_sync_blocked_ips_pull: self.auto_sync_blocked_ips_pull,
            auto_sync_interval_secs: self.auto_sync_interval_secs,
            base_url: self.base_url,
            api_token: self.api_token,
            username: self.username,
            password: self.password,
            verify_tls: self.verify_tls,
            openapi_doc_path: self.openapi_doc_path,
            auth_probe_path: self.auth_probe_path,
            site_list_path: self.site_list_path,
            event_list_path: self.event_list_path,
            blocklist_sync_path: self.blocklist_sync_path,
            blocklist_delete_path: self.blocklist_delete_path,
            blocklist_ip_group_ids: self.blocklist_ip_group_ids,
        }
    }
}

impl SafeLineTestRequest {
    fn into_config(self) -> SafeLineConfig {
        SafeLineConfig {
            enabled: true,
            auto_sync_events: false,
            auto_sync_blocked_ips_push: false,
            auto_sync_blocked_ips_pull: false,
            auto_sync_interval_secs: 0,
            base_url: self.base_url,
            api_token: self.api_token,
            username: self.username,
            password: self.password,
            verify_tls: self.verify_tls,
            openapi_doc_path: self.openapi_doc_path,
            auth_probe_path: self.auth_probe_path,
            site_list_path: self.site_list_path,
            event_list_path: self.event_list_path,
            blocklist_sync_path: self.blocklist_sync_path,
            blocklist_delete_path: self.blocklist_delete_path,
            blocklist_ip_group_ids: self.blocklist_ip_group_ids,
        }
    }
}

impl L4StatsResponse {
    fn disabled() -> Self {
        Self {
            enabled: false,
            connections: crate::l4::connection::ConnectionStats {
                total_connections: 0,
                active_connections: 0,
                blocked_connections: 0,
                rate_limit_hits: 0,
            },
            ddos_events: 0,
            protocol_anomalies: 0,
            traffic: 0,
            defense_actions: 0,
            bloom_stats: None,
            false_positive_stats: None,
            per_port_stats: Vec::new(),
        }
    }

    fn from_stats(stats: crate::l4::inspector::L4Statistics) -> Self {
        let mut per_port_stats = stats.per_port_stats.into_values().collect::<Vec<_>>();
        per_port_stats.sort_by(|left, right| {
            right
                .blocks
                .cmp(&left.blocks)
                .then(right.ddos_events.cmp(&left.ddos_events))
                .then(right.connections.cmp(&left.connections))
                .then(left.port.cmp(&right.port))
        });

        Self {
            enabled: true,
            connections: stats.connections,
            ddos_events: stats.ddos_events,
            protocol_anomalies: stats.protocol_anomalies,
            traffic: stats.traffic,
            defense_actions: stats.defense_actions,
            bloom_stats: stats.bloom_stats,
            false_positive_stats: stats.false_positive_stats,
            per_port_stats,
        }
    }
}

impl From<SafeLineProbeResult> for SafeLineTestResponse {
    fn from(value: SafeLineProbeResult) -> Self {
        Self {
            status: value.status,
            message: value.message,
            openapi_doc_reachable: value.openapi_doc_reachable,
            openapi_doc_status: value.openapi_doc_status,
            authenticated: value.authenticated,
            auth_probe_status: value.auth_probe_status,
        }
    }
}

impl From<SafeLineSiteSummary> for SafeLineSiteResponse {
    fn from(value: SafeLineSiteSummary) -> Self {
        Self {
            id: value.id,
            name: value.name,
            domain: value.domain,
            status: value.status,
            raw: value.raw,
        }
    }
}

impl From<crate::storage::SafeLineSiteMappingEntry> for SafeLineMappingResponse {
    fn from(value: crate::storage::SafeLineSiteMappingEntry) -> Self {
        Self {
            id: value.id,
            safeline_site_id: value.safeline_site_id,
            safeline_site_name: value.safeline_site_name,
            safeline_site_domain: value.safeline_site_domain,
            local_alias: value.local_alias,
            enabled: value.enabled,
            is_primary: value.is_primary,
            notes: value.notes,
            updated_at: value.updated_at,
        }
    }
}

impl SafeLineMappingsUpdateRequest {
    fn into_storage_mappings(
        self,
    ) -> Result<Vec<crate::storage::SafeLineSiteMappingUpsert>, String> {
        let mut primary_count = 0usize;
        let mut mappings = Vec::with_capacity(self.mappings.len());

        for item in self.mappings {
            let safeline_site_id = item.safeline_site_id.trim().to_string();
            let safeline_site_name = item.safeline_site_name.trim().to_string();
            let safeline_site_domain = item.safeline_site_domain.trim().to_string();
            let local_alias = item.local_alias.trim().to_string();
            let notes = item.notes.trim().to_string();

            if safeline_site_id.is_empty() {
                return Err("映射里的雷池站点 ID 不能为空".to_string());
            }
            if local_alias.is_empty() {
                return Err(format!("站点 {} 的本地别名不能为空", safeline_site_id));
            }
            if item.is_primary {
                primary_count += 1;
            }

            mappings.push(crate::storage::SafeLineSiteMappingUpsert {
                safeline_site_id,
                safeline_site_name,
                safeline_site_domain,
                local_alias,
                enabled: item.enabled,
                is_primary: item.is_primary,
                notes,
            });
        }

        if primary_count > 1 {
            return Err("同一时间只能设置一个主站点映射".to_string());
        }

        Ok(mappings)
    }
}

impl From<crate::storage::SafeLineSyncStateEntry> for SafeLineSyncStateResponse {
    fn from(value: crate::storage::SafeLineSyncStateEntry) -> Self {
        Self {
            resource: value.resource,
            last_cursor: value.last_cursor,
            last_success_at: value.last_success_at,
            last_imported_count: value.last_imported_count.max(0) as u32,
            last_skipped_count: value.last_skipped_count.max(0) as u32,
            updated_at: value.updated_at,
        }
    }
}

impl RuleUpsertRequest {
    fn into_rule(self) -> Result<Rule, String> {
        let id = self.id.clone();
        self.into_rule_with_id(id)
    }

    fn into_rule_with_id(self, id: String) -> Result<Rule, String> {
        let id = id.trim().to_string();
        let name = self.name.trim().to_string();
        let pattern = self.pattern.trim().to_string();
        if id.is_empty() {
            return Err("Rule id cannot be empty".to_string());
        }
        if name.is_empty() {
            return Err("Rule name cannot be empty".to_string());
        }
        if pattern.is_empty() {
            return Err("Rule pattern cannot be empty".to_string());
        }

        Ok(Rule {
            id,
            name,
            enabled: self.enabled,
            layer: crate::config::RuleLayer::parse(&self.layer).map_err(|err| err.to_string())?,
            pattern,
            action: crate::config::RuleAction::parse(&self.action)
                .map_err(|err| err.to_string())?,
            severity: crate::config::Severity::parse(&self.severity)
                .map_err(|err| err.to_string())?,
        })
    }
}

impl From<Rule> for RuleResponse {
    fn from(rule: Rule) -> Self {
        Self::from_rule(rule)
    }
}

impl From<crate::storage::SecurityEventEntry> for SecurityEventResponse {
    fn from(event: crate::storage::SecurityEventEntry) -> Self {
        Self {
            id: event.id,
            layer: event.layer,
            provider: event.provider,
            provider_site_id: event.provider_site_id,
            provider_site_name: event.provider_site_name,
            provider_site_domain: event.provider_site_domain,
            action: event.action,
            reason: event.reason,
            source_ip: event.source_ip,
            dest_ip: event.dest_ip,
            source_port: event.source_port,
            dest_port: event.dest_port,
            protocol: event.protocol,
            http_method: event.http_method,
            uri: event.uri,
            http_version: event.http_version,
            created_at: event.created_at,
            handled: event.handled,
            handled_at: event.handled_at,
        }
    }
}

impl From<crate::storage::BlockedIpEntry> for BlockedIpResponse {
    fn from(entry: crate::storage::BlockedIpEntry) -> Self {
        Self {
            id: entry.id,
            provider: entry.provider,
            provider_remote_id: entry.provider_remote_id,
            ip: entry.ip,
            reason: entry.reason,
            blocked_at: entry.blocked_at,
            expires_at: entry.expires_at,
        }
    }
}

impl EventsQueryParams {
    fn into_query(self) -> Result<crate::storage::SecurityEventQuery, String> {
        Ok(crate::storage::SecurityEventQuery {
            limit: self.limit.unwrap_or(50),
            offset: self.offset.unwrap_or(0),
            layer: self.layer,
            provider: self.provider,
            provider_site_id: self.provider_site_id,
            source_ip: self.source_ip,
            action: self.action,
            blocked_only: self.blocked_only.unwrap_or(false),
            handled_only: self.handled_only,
            created_from: self.created_from,
            created_to: self.created_to,
            sort_by: parse_event_sort_field(self.sort_by.as_deref())?,
            sort_direction: parse_sort_direction(self.sort_direction.as_deref())?,
        })
    }
}

impl BlockedIpsQueryParams {
    fn into_query(self) -> Result<crate::storage::BlockedIpQuery, String> {
        Ok(crate::storage::BlockedIpQuery {
            limit: self.limit.unwrap_or(50),
            offset: self.offset.unwrap_or(0),
            source_scope: parse_blocked_ip_source_scope(self.source_scope.as_deref())?,
            provider: self.provider,
            ip: self.ip,
            active_only: self.active_only.unwrap_or(false),
            blocked_from: self.blocked_from,
            blocked_to: self.blocked_to,
            sort_by: parse_blocked_ip_sort_field(self.sort_by.as_deref())?,
            sort_direction: parse_sort_direction(self.sort_direction.as_deref())?,
        })
    }
}

fn parse_blocked_ip_source_scope(
    value: Option<&str>,
) -> Result<crate::storage::BlockedIpSourceScope, String> {
    match value.unwrap_or("all").trim().to_ascii_lowercase().as_str() {
        "all" => Ok(crate::storage::BlockedIpSourceScope::All),
        "local" => Ok(crate::storage::BlockedIpSourceScope::Local),
        "remote" => Ok(crate::storage::BlockedIpSourceScope::Remote),
        other => Err(format!("Unsupported blocked IP source_scope '{}'", other)),
    }
}

fn parse_sort_direction(value: Option<&str>) -> Result<crate::storage::SortDirection, String> {
    match value.unwrap_or("desc").trim().to_ascii_lowercase().as_str() {
        "asc" => Ok(crate::storage::SortDirection::Asc),
        "desc" => Ok(crate::storage::SortDirection::Desc),
        other => Err(format!("Unsupported sort_direction '{}'", other)),
    }
}

fn parse_event_sort_field(value: Option<&str>) -> Result<crate::storage::EventSortField, String> {
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

fn parse_blocked_ip_sort_field(
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

fn non_empty_string(value: String) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn runtime_profile_label(profile: RuntimeProfile) -> &'static str {
    match profile {
        RuntimeProfile::Minimal => "minimal",
        RuntimeProfile::Standard => "standard",
    }
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
        assert!(query.active_only);
        assert_eq!(query.blocked_from, Some(300));
        assert_eq!(query.blocked_to, Some(400));
        assert!(matches!(
            query.sort_by,
            crate::storage::BlockedIpSortField::Ip
        ));
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
}
