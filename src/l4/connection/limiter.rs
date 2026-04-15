use crate::config::L4Config;
use dashmap::DashMap;
use log::{info, warn};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

pub const RATE_LIMIT_BLOCK_DURATION_SECS: u64 = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitDecision {
    Allowed,
    Rejected,
    RejectedAndBlocked,
}

pub struct ConnectionLimiter {
    config: L4Config,
    blocked_ips: DashMap<IpAddr, BlockedIp>,
    request_counters: DashMap<IpAddr, RateLimitEntry>,
    total_blocked: AtomicU64,
    total_rate_limit_hits: AtomicU64,
}

#[derive(Debug, Clone)]
struct BlockedIp {
    blocked_at: Instant,
    block_duration: Duration,
    reason: String,
}

#[derive(Debug, Clone)]
struct RateLimitEntry {
    window_started: Instant,
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
            blocked_ips: DashMap::new(),
            request_counters: DashMap::new(),
            total_blocked: AtomicU64::new(0),
            total_rate_limit_hits: AtomicU64::new(0),
        }
    }

    pub async fn start(&self) -> anyhow::Result<()> {
        info!("Connection Limiter started");
        Ok(())
    }

    pub fn check(&self, ip: &IpAddr) -> RateLimitDecision {
        if self.is_blocked(ip) {
            warn!("Connection rejected - IP {} is blocked", ip);
            return RateLimitDecision::Rejected;
        }

        let now = Instant::now();
        {
            let mut entry = self.request_counters.entry(*ip).or_insert(RateLimitEntry {
                window_started: now,
                count: 0,
            });

            if now.duration_since(entry.window_started) >= Duration::from_secs(1) {
                entry.window_started = now;
                entry.count = 0;
            }

            if entry.count < self.config.connection_rate_limit {
                entry.count += 1;
                return RateLimitDecision::Allowed;
            }
        }

        self.total_rate_limit_hits.fetch_add(1, Ordering::Relaxed);
        let newly_blocked = self.block_ip(
            ip,
            "rate limit exceeded",
            Duration::from_secs(RATE_LIMIT_BLOCK_DURATION_SECS),
        );
        warn!(
            "Connection rejected - IP {} exceeded rate limit {}",
            ip, self.config.connection_rate_limit
        );
        if newly_blocked {
            RateLimitDecision::RejectedAndBlocked
        } else {
            RateLimitDecision::Rejected
        }
    }

    pub fn is_blocked(&self, ip: &IpAddr) -> bool {
        if let Some(blocked) = self.blocked_ips.get(ip) {
            return blocked.blocked_at.elapsed() < blocked.block_duration;
        }
        self.blocked_ips.remove(ip);
        false
    }

    pub fn block_ip(&self, ip: &IpAddr, reason: &str, duration: Duration) -> bool {
        if self.blocked_ips.len() >= self.config.max_blocked_ips
            && !self.blocked_ips.contains_key(ip)
        {
            warn!(
                "Blocked IP table is full (limit: {}), skipping new block for {}",
                self.config.max_blocked_ips, ip
            );
            return false;
        }

        let inserted = self
            .blocked_ips
            .insert(
                *ip,
                BlockedIp {
                    blocked_at: Instant::now(),
                    block_duration: duration,
                    reason: reason.to_string(),
                },
            )
            .is_none();
        self.total_blocked.fetch_add(1, Ordering::Relaxed);
        warn!("Blocked IP {} for {:?}: {}", ip, duration, reason);
        inserted
    }

    pub fn unblock_ip(&self, ip: &IpAddr) -> bool {
        let removed = self.blocked_ips.remove(ip).is_some();
        if removed {
            self.request_counters.remove(ip);
        }

        removed
    }

    pub fn cleanup_expired(&self) {
        let ttl = Duration::from_secs(self.config.state_ttl_secs);
        let expired_blocked = self
            .blocked_ips
            .iter()
            .filter_map(|entry| {
                let blocked = entry.value();
                let elapsed = blocked.blocked_at.elapsed();
                (elapsed >= blocked.block_duration || elapsed >= ttl)
                    .then(|| (*entry.key(), blocked.reason.clone()))
            })
            .collect::<Vec<_>>();
        for (ip, reason) in expired_blocked {
            self.blocked_ips.remove(&ip);
            info!("Unblocked expired IP {} ({})", ip, reason);
        }

        let stale_counters = self
            .request_counters
            .iter()
            .filter_map(|entry| {
                (entry.value().window_started.elapsed() >= ttl).then(|| *entry.key())
            })
            .collect::<Vec<_>>();
        for ip in stale_counters {
            self.request_counters.remove(&ip);
        }
    }

    pub fn get_blocked_count(&self) -> u64 {
        let ttl = Duration::from_secs(self.config.state_ttl_secs);
        let expired = self
            .blocked_ips
            .iter()
            .filter_map(|entry| {
                let elapsed = entry.value().blocked_at.elapsed();
                (elapsed >= entry.value().block_duration || elapsed >= ttl).then(|| *entry.key())
            })
            .collect::<Vec<_>>();
        for ip in expired {
            self.blocked_ips.remove(&ip);
        }
        self.blocked_ips.len() as u64
    }

    pub fn get_rate_limit_hits(&self) -> u64 {
        self.total_rate_limit_hits.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn limiter() -> ConnectionLimiter {
        ConnectionLimiter::new(L4Config {
            connection_rate_limit: 1,
            max_blocked_ips: 8,
            state_ttl_secs: 30,
            ..L4Config::default()
        })
    }

    #[test]
    fn check_distinguishes_new_blocks_from_existing_rejections() {
        let limiter = limiter();
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));

        assert_eq!(limiter.check(&ip), RateLimitDecision::Allowed);
        assert_eq!(limiter.check(&ip), RateLimitDecision::RejectedAndBlocked);
        assert_eq!(limiter.check(&ip), RateLimitDecision::Rejected);
        assert_eq!(limiter.get_blocked_count(), 1);
    }

    #[test]
    fn unblock_ip_removes_runtime_block_immediately() {
        let limiter = limiter();
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 11));

        assert_eq!(limiter.check(&ip), RateLimitDecision::Allowed);
        assert_eq!(limiter.check(&ip), RateLimitDecision::RejectedAndBlocked);
        assert!(limiter.unblock_ip(&ip));
        assert_eq!(limiter.get_blocked_count(), 0);
        assert_eq!(limiter.check(&ip), RateLimitDecision::Allowed);
    }
}
