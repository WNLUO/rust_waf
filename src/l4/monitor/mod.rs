pub mod tracker;
pub mod alerter;
pub mod logger;

use crate::config::L4Config;
use log::{info, debug};

pub use tracker::StateTracker;
pub use alerter::Alerter;
pub use logger::MonitorLogger;

pub struct MonitorManager {
    config: L4Config,
}

impl MonitorManager {
    pub fn new(config: L4Config) -> Self {
        info!("Initializing Monitor Manager");
        Self {
            config,
        }
    }

    pub async fn start(&self) -> anyhow::Result<()> {
        info!("Monitor Manager started");
        Ok(())
    }

    pub fn track_packet(&self, _packet: &crate::core::PacketInfo) {
        debug!("Tracking packet");
    }

    pub fn alert_threat(&self, _packet: &crate::core::PacketInfo, reason: &str) {
        info!("ALERT: Threat detected - {}", reason);
    }
}
