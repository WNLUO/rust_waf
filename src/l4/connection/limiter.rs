use crate::config::L4Config;
use log::{info, warn};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

pub const RATE_LIMIT_BLOCK_DURATION_SECS: u64 = 30;

pub struct ConnectionLimiter {
    config: L4Config,
    blocked_ips: Mutex<HashMap<IpAddr, BlockedIp>>,
    request_counters: Mutex<HashMap<IpAddr, RateLimitEntry>>,
    total_blocked: AtomicU64,
    total_rate_limit_hits: AtomicU64,
}

#[derive(Debug, Clone)]
struct BlockedIp {
    blocked_at: std::time::Instant,
    block_duration: std::time::Duration,
    reason: String,
}

#[derive(Debug, Clone)]
struct RateLimitEntry {
    window_started: std::time::Instant,
    count: usize,
}

impl ConnectionLimiter {
    pub fn new(config: L4Config) -> Self {
        info!(
            "Initializing Connection Limiter with max rate: {}",
            config.connection_rate_limit
        );
        Self {
            config,
            blocked_ips: Mutex::new(HashMap::new()),
            request_counters: Mutex::new(HashMap::new()),
            total_blocked: AtomicU64::new(0),
            total_rate_limit_hits: AtomicU64::new(0),
        }
    }

    pub async fn start(&self) -> anyhow::Result<()> {
        info!("Connection Limiter started");
        Ok(())
    }

    pub fn check(&self, ip: &IpAddr) -> bool {
        // Check if IP is blocked
        if self.is_blocked(ip) {
            warn!("Connection rejected - IP {} is blocked", ip);
            return false;
        }

        let mut request_counters = self
            .request_counters
            .lock()
            .expect("request_counters mutex poisoned");
        let now = std::time::Instant::now();
        let entry = request_counters.entry(*ip).or_insert(RateLimitEntry {
            window_started: now,
            count: 0,
        });

        if now.duration_since(entry.window_started) >= std::time::Duration::from_secs(1) {
            entry.window_started = now;
            entry.count = 0;
        }

        if entry.count >= self.config.connection_rate_limit {
            self.total_rate_limit_hits.fetch_add(1, Ordering::Relaxed);
            drop(request_counters);
            self.block_ip(
                ip,
                "rate limit exceeded",
                std::time::Duration::from_secs(RATE_LIMIT_BLOCK_DURATION_SECS),
            );
            warn!(
                "Connection rejected - IP {} exceeded rate limit {}",
                ip, self.config.connection_rate_limit
            );
            return false;
        }

        entry.count += 1;
        true
    }

    pub fn is_blocked(&self, ip: &IpAddr) -> bool {
        let blocked_ips = self.blocked_ips.lock().expect("blocked_ips mutex poisoned");
        if let Some(blocked) = blocked_ips.get(ip) {
            let elapsed = blocked.blocked_at.elapsed();
            if elapsed < blocked.block_duration {
                return true;
            }
        }
        false
    }

    pub fn block_ip(&self, ip: &IpAddr, reason: &str, duration: std::time::Duration) {
        let mut blocked_ips = self.blocked_ips.lock().expect("blocked_ips mutex poisoned");
        if blocked_ips.len() >= self.config.max_blocked_ips {
            warn!(
                "Blocked IP table is full (limit: {}), skipping new block for {}",
                self.config.max_blocked_ips, ip
            );
            return;
        }

        blocked_ips.insert(
            *ip,
            BlockedIp {
                blocked_at: std::time::Instant::now(),
                block_duration: duration,
                reason: reason.to_string(),
            },
        );
        self.total_blocked.fetch_add(1, Ordering::Relaxed);
        warn!("Blocked IP {} for {:?}: {}", ip, duration, reason);
    }

    pub fn cleanup_expired(&self) {
        let ttl = std::time::Duration::from_secs(self.config.state_ttl_secs);
        let mut blocked_ips = self.blocked_ips.lock().expect("blocked_ips mutex poisoned");
        blocked_ips.retain(|ip, blocked| {
            let keep = blocked.blocked_at.elapsed() < blocked.block_duration
                && blocked.blocked_at.elapsed() < ttl;
            if !keep {
                info!("Unblocked expired IP {} ({})", ip, blocked.reason);
            }
            keep
        });

        let mut request_counters = self
            .request_counters
            .lock()
            .expect("request_counters mutex poisoned");
        request_counters.retain(|_, entry| entry.window_started.elapsed() < ttl);
    }

    pub fn get_blocked_count(&self) -> u64 {
        self.total_blocked.load(Ordering::Relaxed)
    }

    pub fn get_rate_limit_hits(&self) -> u64 {
        self.total_rate_limit_hits.load(Ordering::Relaxed)
    }
}
