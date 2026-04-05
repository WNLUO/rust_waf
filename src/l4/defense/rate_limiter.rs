use crate::config::L4Config;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use log::{info, debug};

pub struct DefenseRateLimiter {
    config: L4Config,
    rate_limits: HashMap<IpAddr, RateLimitEntry>,
    total_rate_limited: AtomicU64,
}

#[derive(Debug, Clone)]
struct RateLimitEntry {
    current_rate: usize,
    limit: usize,
    window_start: std::time::Instant,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RateLimiterStats {
    pub currently_limited: usize,
    pub total_limitations: u64,
}

impl DefenseRateLimiter {
    pub fn new(config: L4Config) -> Self {
        info!("Initializing Defense Rate Limiter");
        Self {
            config,
            rate_limits: HashMap::new(),
            total_rate_limited: AtomicU64::new(0),
        }
    }

    pub async fn start(&self) -> anyhow::Result<()> {
        info!("Defense Rate Limiter started");
        Ok(())
    }

    pub fn check(&self, ip: &IpAddr) -> bool {
        if let Some(entry) = self.rate_limits.get(ip) {
            let elapsed = entry.window_start.elapsed();
            if elapsed.as_secs() >= 1 {
                // Reset window
                return true;
            }

            if entry.current_rate >= entry.limit {
                return false;
            }
        }

        true
    }

    pub fn record_request(&mut self, ip: &IpAddr) {
        let entry = self.rate_limits.entry(*ip).or_insert_with(|| {
            RateLimitEntry {
                current_rate: 0,
                limit: self.config.connection_rate_limit,
                window_start: std::time::Instant::now(),
            }
        });

        entry.current_rate += 1;

        if entry.current_rate > entry.limit {
            self.total_rate_limited.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn get_stats(&self) -> RateLimiterStats {
        RateLimiterStats {
            currently_limited: self.rate_limits.len(),
            total_limitations: self.total_rate_limited.load(Ordering::Relaxed),
        }
    }
}
