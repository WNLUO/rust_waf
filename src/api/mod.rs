mod auth;
mod conversions;
mod error;
mod events_handlers;
mod metrics;
mod plugin_install;
mod realtime;
mod router;
mod rules;
mod safeline_handlers;
mod settings_handlers;
mod sites_handlers;
mod state;
mod system_handlers;
#[cfg(test)]
mod tests;
mod types;

use self::error::{map_storage_write_error, ApiError, ApiResult};
use self::metrics::build_metrics_response;
use self::plugin_install::{
    install_rule_action_plugin_from_bytes, install_rule_action_plugin_from_url,
};
use self::state::{
    non_empty_string, persisted_config, rules_store, runtime_profile_label, sqlite_store,
    unix_timestamp, ApiState,
};
use self::types::*;
use crate::core::WafContext;
use axum::{
    extract::Json as ExtractJson,
    extract::{Path, Query, State},
    http::StatusCode,
    Json, Router,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::broadcast;

pub struct ApiServer {
    addr: SocketAddr,
    context: Arc<WafContext>,
}

impl ApiServer {
    pub fn new(addr: SocketAddr, context: Arc<WafContext>) -> Self {
        Self { addr, context }
    }

    pub async fn start(self) -> anyhow::Result<()> {
        // Shared across high-frequency traffic deltas and dashboard snapshots.
        // Keep capacity higher to reduce lag/drop under burst traffic.
        let realtime_tx = broadcast::channel(1024).0;
        realtime::spawn_sampler(Arc::clone(&self.context), realtime_tx.clone());
        realtime::spawn_storage_bridge(Arc::clone(&self.context), realtime_tx.clone());
        realtime::spawn_traffic_bridge(Arc::clone(&self.context), realtime_tx.clone());
        let ws_tickets = Arc::new(realtime::WsTicketStore::default());
        let state = ApiState {
            context: Arc::clone(&self.context),
            realtime_tx,
            ws_tickets,
        };
        let app = router::build_router(state);

        let listener = TcpListener::bind(self.addr).await?;
        log::info!("API server listening on {}", self.addr);

        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await?;
        Ok(())
    }
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

#[doc(hidden)]
pub fn build_test_router(context: Arc<WafContext>) -> Router {
    let realtime_tx = broadcast::channel(8).0;
    realtime::spawn_traffic_bridge(Arc::clone(&context), realtime_tx.clone());
    router::build_router(ApiState {
        context,
        realtime_tx,
        ws_tickets: Arc::new(realtime::WsTicketStore::default()),
    })
}
