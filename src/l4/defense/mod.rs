pub mod blocker;
pub mod rate_limiter;
pub mod cleanup;

use crate::config::L4Config;
use log::info;

pub use blocker::BlockManager;
pub use rate_limiter::DefenseRateLimiter;
pub use cleanup::CleanupManager;

pub struct DefenseManager {
    config: L4Config,
}

impl DefenseManager {
    pub fn new(config: L4Config) -> Self {
        info!("Initializing Defense Manager");
        Self {
            config,
        }
    }

    pub async fn start(&self) -> anyhow::Result<()> {
        info!("Defense Manager started");
        Ok(())
    }

    pub fn block(&self, _packet: &crate::core::PacketInfo, reason: &str) {
        info!("Would block packet: {}", reason);
    }

    pub fn unblock(&self, _ip: &std::net::IpAddr) {
        info!("Would unblock IP");
    }

    pub fn get_stats(&self) -> DefenseStats {
        DefenseStats {
            blocked_ips: 0,
            rate_limited: 0,
            cleanup_actions: 0,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DefenseStats {
    pub blocked_ips: usize,
    pub rate_limited: usize,
    pub cleanup_actions: usize,
}
