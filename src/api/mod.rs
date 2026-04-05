use axum::{routing::get, Json, Router};
use serde::Serialize;
use std::net::SocketAddr;
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
}

pub struct ApiServer {
    addr: SocketAddr,
}

impl ApiServer {
    pub fn new(addr: SocketAddr) -> Self {
        Self { addr }
    }

    pub async fn start(self) -> anyhow::Result<()> {
        let app = Router::new()
            .route("/health", get(health_handler))
            .route("/metrics", get(metrics_handler));

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

async fn metrics_handler() -> Json<MetricsResponse> {
    // In production, this would get real metrics
    Json(MetricsResponse {
        total_packets: 0,
        blocked_packets: 0,
        blocked_l4: 0,
        blocked_l7: 0,
        total_bytes: 0,
    })
}
