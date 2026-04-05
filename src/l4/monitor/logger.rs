use crate::config::L4Config;
use crate::core::PacketInfo;
use std::sync::atomic::{AtomicU64, Ordering};
use log::{info, warn, error};

pub struct MonitorLogger {
    config: L4Config,
    threats_logged: AtomicU64,
}

impl MonitorLogger {
    pub fn new(config: L4Config) -> Self {
        info!("Initializing Monitor Logger");
        Self {
            config,
            threats_logged: AtomicU64::new(0),
        }
    }

    pub async fn start(&self) -> anyhow::Result<()> {
        info!("Monitor Logger started");
        Ok(())
    }

    pub fn log_threat(&self, packet: &PacketInfo, reason: &str) {
        self.threats_logged.fetch_add(1, Ordering::Relaxed);
        warn!("THREAT LOGGED: {} from {}:{} to {}:{} - {}",
              std::time::SystemTime::now()
                  .duration_since(std::time::UNIX_EPOCH)
                  .unwrap()
                  .as_secs(),
              packet.source_ip, packet.source_port,
              packet.dest_ip, packet.dest_port,
              reason);
    }

    pub fn log_info(&self, message: &str) {
        info!("{}", message);
    }

    pub fn log_error(&self, error: &str) {
        error!("{}", error);
    }

    pub fn get_threat_count(&self) -> u64 {
        self.threats_logged.load(Ordering::Relaxed)
    }
}
