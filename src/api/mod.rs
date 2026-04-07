use crate::config::Rule;
use crate::core::WafContext;
use axum::{
    extract::Json as ExtractJson,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{delete, get},
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
    source_ip: Option<String>,
    action: Option<String>,
    blocked_only: Option<bool>,
    created_from: Option<i64>,
    created_to: Option<i64>,
    sort_by: Option<String>,
    sort_direction: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct BlockedIpsQueryParams {
    limit: Option<u32>,
    offset: Option<u32>,
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
            .route("/events", get(list_security_events_handler))
            .route("/blocked-ips", get(list_blocked_ips_handler))
            .route("/blocked-ips/:id", delete(delete_blocked_ip_handler))
            .route("/rules", get(list_rules_handler).post(create_rule_handler))
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
        Err(ApiError::conflict(format!("Rule '{}' already exists", rule.id)))
    }
}

async fn update_rule_handler(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    ExtractJson(payload): ExtractJson<RuleUpsertRequest>,
) -> ApiResult<Json<WriteStatusResponse>> {
    let store = rules_store(&state)?;
    let rule = payload.into_rule_with_id(id).map_err(ApiError::bad_request)?;
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
    let deleted = store
        .delete_blocked_ip(id)
        .await
        .map_err(ApiError::internal)?;

    if deleted {
        Ok(Json(WriteStatusResponse {
            success: true,
            message: format!("Blocked IP record '{}' removed", id),
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
            layer: crate::config::RuleLayer::parse(&self.layer)
                .map_err(|err| err.to_string())?,
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
        }
    }
}

impl From<crate::storage::BlockedIpEntry> for BlockedIpResponse {
    fn from(entry: crate::storage::BlockedIpEntry) -> Self {
        Self {
            id: entry.id,
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
            source_ip: self.source_ip,
            action: self.action,
            blocked_only: self.blocked_only.unwrap_or(false),
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
            ip: self.ip,
            active_only: self.active_only.unwrap_or(false),
            blocked_from: self.blocked_from,
            blocked_to: self.blocked_to,
            sort_by: parse_blocked_ip_sort_field(self.sort_by.as_deref())?,
            sort_direction: parse_sort_direction(self.sort_direction.as_deref())?,
        })
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
            source_ip: Some("10.0.0.1".to_string()),
            action: Some("block".to_string()),
            blocked_only: Some(true),
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
            sort_direction: Some("sideways".to_string()),
            ..BlockedIpsQueryParams::default()
        }
        .into_query();
        assert!(invalid_blocked.is_err());
    }
}
