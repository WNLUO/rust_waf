use crate::core::WafContext;
use axum::{extract::State, routing::get, Json, Router};
use serde::Serialize;
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
