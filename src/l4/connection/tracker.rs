use crate::config::L4Config;
use std::sync::atomic::{AtomicU64, Ordering};
use log::info;

pub struct ConnectionTracker {
    total_connections: AtomicU64,
    active_connections: AtomicU64,
}

impl ConnectionTracker {
    pub fn new(_config: L4Config) -> Self {
        info!("Initializing Connection Tracker");
        Self {
            total_connections: AtomicU64::new(0),
            active_connections: AtomicU64::new(0),
        }
    }

    pub async fn start(&self) -> anyhow::Result<()> {
        info!("Connection Tracker started");
        Ok(())
    }

    pub fn track(&self, _packet: &crate::core::PacketInfo) {
        self.total_connections.fetch_add(1, Ordering::Relaxed);
        self.active_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn get_total_connections(&self) -> u64 {
        self.total_connections.load(Ordering::Relaxed)
    }

    pub fn get_active_connections(&self) -> u64 {
        self.active_connections.load(Ordering::Relaxed)
    }

    pub fn cleanup_inactive(&self, _timeout: std::time::Duration) {
        let old_active = self.active_connections.swap(0, Ordering::Relaxed);
        if old_active > 0 {
            info!("Cleaned up {} inactive connections", old_active);
        }
    }
}
