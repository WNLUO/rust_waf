use crate::config::L4Config;
use crate::core::PacketInfo;
use std::sync::atomic::{AtomicU64, Ordering};
use log::{info, debug};

pub struct StateTracker {
    config: L4Config,
    total_tracked: AtomicU64,
}

impl StateTracker {
    pub fn new(config: L4Config) -> Self {
        info!("Initializing State Tracker");
        Self {
            config,
            total_tracked: AtomicU64::new(0),
        }
    }

    pub async fn start(&self) -> anyhow::Result<()> {
        info!("State Tracker started");
        Ok(())
    }

    pub fn track_packet(&self, packet: &PacketInfo) {
        self.total_tracked.fetch_add(1, Ordering::Relaxed);
        debug!("Tracking packet from {}", packet.source_ip);
    }

    pub fn get_total_tracked(&self) -> u64 {
        self.total_tracked.load(Ordering::Relaxed)
    }
}
