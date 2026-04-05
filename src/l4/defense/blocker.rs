use crate::config::L4Config;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use log::{info, debug, warn};

pub struct BlockManager {
    config: L4Config,
    blocked_ips: HashMap<IpAddr, BlockEntry>,
    total_blocked: AtomicU64,
}

#[derive(Debug, Clone)]
struct BlockEntry {
    blocked_at: Instant,
    block_duration: Duration,
    reason: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct BlockerStats {
    pub currently_blocked: usize,
    pub total_blocks: u64,
}

impl BlockManager {
    pub fn new(config: L4Config) -> Self {
        info!("Initializing Block Manager");
        Self {
            config,
            blocked_ips: HashMap::new(),
            total_blocked: AtomicU64::new(0),
        }
    }

    pub async fn start(&self) -> anyhow::Result<()> {
        info!("Block Manager started");
        self.start_cleanup_task();
        Ok(())
    }

    pub fn block_ip(&mut self, ip: &IpAddr, reason: &str) {
        let now = Instant::now();
        let duration = self.calculate_block_duration(reason);

        self.blocked_ips.insert(*ip, BlockEntry {
            blocked_at: now,
            block_duration: duration,
            reason: reason.to_string(),
        });

        self.total_blocked.fetch_add(1, Ordering::Relaxed);
        warn!("Blocked IP {} for {:?}: {}", ip, duration, reason);
    }

    pub fn unblock_ip(&mut self, ip: &IpAddr) {
        if self.blocked_ips.remove(ip).is_some() {
            info!("Unblocked IP {}", ip);
        }
    }

    pub fn is_blocked(&mut self, ip: &IpAddr) -> bool {
        if let Some(entry) = self.blocked_ips.get(ip) {
            let elapsed = entry.blocked_at.elapsed();
            if elapsed < entry.block_duration {
                return true;
            } else {
                // Block expired
                self.blocked_ips.remove(ip);
            }
        }
        false
    }

    fn calculate_block_duration(&self, reason: &str) -> Duration {
        // Calculate block duration based on reason
        if reason.contains("DDoS") || reason.contains("Flood") {
            Duration::from_secs(3600) // 1 hour for DDoS
        } else if reason.contains("scan") {
            Duration::from_secs(600) // 10 minutes for scanning
        } else {
            Duration::from_secs(300) // 5 minutes default
        }
    }

    pub fn get_stats(&self) -> BlockerStats {
        BlockerStats {
            currently_blocked: self.blocked_ips.len(),
            total_blocks: self.total_blocked.load(Ordering::Relaxed),
        }
    }

    fn start_cleanup_task(&self) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                debug!("Block Manager cleanup task running");
            }
        });
    }
}
