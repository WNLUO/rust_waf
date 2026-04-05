use crate::config::Rule;
use crate::core::WafContext;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
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
}

#[derive(Debug, Serialize)]
pub struct MetricsResponse {
    total_packets: u64,
    blocked_packets: u64,
    blocked_l4: u64,
    blocked_l7: u64,
    total_bytes: u64,
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
pub struct CreateRuleRequest {
    id: String,
    name: String,
    enabled: bool,
    layer: String,
    pattern: String,
    action: String,
    severity: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateRuleRequest {
    name: String,
    enabled: bool,
    layer: String,
    pattern: String,
    action: String,
    severity: String,
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

async fn health_handler() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "healthy".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
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
    Json(payload): Json<CreateRuleRequest>,
) -> ApiResult<(StatusCode, Json<RuleResponse>)> {
    let store = rules_store(&state)?;
    let rule = payload.into_rule().map_err(ApiError::bad_request)?;

    let inserted = store.insert_rule(&rule).await.map_err(ApiError::internal)?;
    if !inserted {
        return Err(ApiError::conflict(format!(
            "Rule '{}' already exists",
            rule.id
        )));
    }

    state
        .context
        .refresh_rules_from_storage()
        .await
        .map_err(ApiError::internal)?;

    Ok((StatusCode::CREATED, Json(RuleResponse::from(rule))))
}

async fn update_rule_handler(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    Json(payload): Json<UpdateRuleRequest>,
) -> ApiResult<Json<RuleResponse>> {
    let store = rules_store(&state)?;
    if store
        .load_rule(&id)
        .await
        .map_err(ApiError::internal)?
        .is_none()
    {
        return Err(ApiError::not_found(format!("Rule '{}' not found", id)));
    }

    let rule = payload.into_rule(id).map_err(ApiError::bad_request)?;
    store.upsert_rule(&rule).await.map_err(ApiError::internal)?;
    state
        .context
        .refresh_rules_from_storage()
        .await
        .map_err(ApiError::internal)?;

    Ok(Json(RuleResponse::from(rule)))
}

async fn delete_rule_handler(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    let store = rules_store(&state)?;
    let deleted = store.delete_rule(&id).await.map_err(ApiError::internal)?;
    if !deleted {
        return Err(ApiError::not_found(format!("Rule '{}' not found", id)));
    }

    state
        .context
        .refresh_rules_from_storage()
        .await
        .map_err(ApiError::internal)?;

    Ok(StatusCode::NO_CONTENT)
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
    });
    let sqlite_enabled = storage_summary.is_some();
    let storage_summary = storage_summary.unwrap_or_default();

    MetricsResponse {
        total_packets: snapshot.total_packets,
        blocked_packets: snapshot.blocked_packets,
        blocked_l4: snapshot.blocked_l4,
        blocked_l7: snapshot.blocked_l7,
        total_bytes: snapshot.total_bytes,
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

impl From<Rule> for RuleResponse {
    fn from(rule: Rule) -> Self {
        Self::from_rule(rule)
    }
}

impl CreateRuleRequest {
    fn into_rule(self) -> Result<Rule, String> {
        Ok(Rule {
            id: self.id,
            name: self.name,
            enabled: self.enabled,
            layer: crate::config::RuleLayer::parse(&self.layer)?,
            pattern: self.pattern,
            action: crate::config::RuleAction::parse(&self.action)?,
            severity: crate::config::Severity::parse(&self.severity)?,
        })
    }
}

impl UpdateRuleRequest {
    fn into_rule(self, id: String) -> Result<Rule, String> {
        Ok(Rule {
            id,
            name: self.name,
            enabled: self.enabled,
            layer: crate::config::RuleLayer::parse(&self.layer)?,
            pattern: self.pattern,
            action: crate::config::RuleAction::parse(&self.action)?,
            severity: crate::config::Severity::parse(&self.severity)?,
        })
    }
}

fn rules_store(state: &ApiState) -> ApiResult<&crate::storage::SqliteStore> {
    if !state.context.config.sqlite_enabled {
        return Err(ApiError::conflict(
            "SQLite storage is disabled in configuration".to_string(),
        ));
    }
    if !state.context.config.sqlite_rules_enabled {
        return Err(ApiError::conflict(
            "SQLite-backed rules are disabled in configuration".to_string(),
        ));
    }

    state
        .context
        .sqlite_store
        .as_deref()
        .ok_or_else(|| ApiError::conflict("SQLite store is unavailable".to_string()))
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
        assert_eq!(response.active_rules, 4);
        assert!(response.sqlite_enabled);
        assert_eq!(response.persisted_security_events, 7);
        assert_eq!(response.persisted_blocked_ips, 2);
        assert_eq!(response.persisted_rules, 5);
        assert_eq!(response.last_persisted_event_at, Some(1234567890));
        assert_eq!(response.last_rule_update_at, Some(1234567899));
    }

    #[test]
    fn test_create_rule_request_into_rule() {
        let rule = CreateRuleRequest {
            id: "rule-1".to_string(),
            name: "Block SQLi".to_string(),
            enabled: true,
            layer: "l7".to_string(),
            pattern: "(?i)select".to_string(),
            action: "block".to_string(),
            severity: "high".to_string(),
        }
        .into_rule()
        .unwrap();

        assert_eq!(rule.id, "rule-1");
        assert_eq!(rule.layer, RuleLayer::L7);
        assert_eq!(rule.action, RuleAction::Block);
        assert_eq!(rule.severity, Severity::High);
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
}
