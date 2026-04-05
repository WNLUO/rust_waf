pub mod monitor;
pub mod limiter;
pub mod tracker;

use crate::config::L4Config;
use log::info;

pub use monitor::ConnectionMonitor;
pub use limiter::ConnectionLimiter;
pub use tracker::ConnectionTracker;

pub struct ConnectionManager {
    monitor: ConnectionMonitor,
    limiter: ConnectionLimiter,
    tracker: ConnectionTracker,
}

impl ConnectionManager {
    pub fn new(config: L4Config) -> Self {
        info!("Initializing Connection Manager");
        Self {
            monitor: ConnectionMonitor::new(config.clone()),
            limiter: ConnectionLimiter::new(config.clone()),
            tracker: ConnectionTracker::new(config.clone()),
        }
    }

    pub async fn start(&self) -> anyhow::Result<()> {
        info!("Starting Connection Manager");
        self.monitor.start().await?;
        self.limiter.start().await?;
        self.tracker.start().await?;
        Ok(())
    }

    pub fn track(&self, packet: &crate::core::PacketInfo) {
        self.monitor.record_connection(&packet.source_ip);
        self.tracker.track(packet);
    }

    pub fn check_rate_limit(&self, ip: &std::net::IpAddr) -> bool {
        self.limiter.check(ip)
    }

    pub fn get_stats(&self) -> ConnectionStats {
        ConnectionStats {
            total_connections: self.tracker.get_total_connections(),
            active_connections: self.tracker.get_active_connections(),
            blocked_connections: self.limiter.get_blocked_count(),
            rate_limit_hits: self.limiter.get_rate_limit_hits(),
        }
    }

    pub fn maintenance_tick(&self) {
        self.tracker.cleanup_inactive(std::time::Duration::from_secs(30));
        self.limiter.cleanup_expired();
        self.monitor.maintenance_tick();
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ConnectionStats {
    pub total_connections: u64,
    pub active_connections: u64,
    pub blocked_connections: u64,
    pub rate_limit_hits: u64,
}
