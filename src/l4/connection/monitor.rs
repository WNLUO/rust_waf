use crate::config::L4Config;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use log::info;

pub struct ConnectionMonitor {
    total_connections: AtomicU64,
}

impl ConnectionMonitor {
    pub fn new(config: L4Config) -> Self {
        info!("Initializing Connection Monitor with rate limit: {}", config.connection_rate_limit);
        Self {
            total_connections: AtomicU64::new(0),
        }
    }

    pub async fn start(&self) -> anyhow::Result<()> {
        info!("Connection Monitor started");
        Ok(())
    }

    pub fn record_connection(&self, _ip: &IpAddr) {
        self.total_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn maintenance_tick(&self) {
        let _ = self.total_connections.load(Ordering::Relaxed);
    }
}
