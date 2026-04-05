use crate::config::L4Config;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use log::{info, debug};

pub struct SynCookieHandler {
    config: L4Config,
    active_cookies: HashMap<IpAddr, CookieEntry>,
    generated_count: AtomicU64,
    validated_count: AtomicU64,
    failed_count: AtomicU64,
}

#[derive(Debug, Clone)]
struct CookieEntry {
    cookie: u32,
    generated_at: std::time::Instant,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SynCookieStats {
    pub generated: u64,
    pub validated: u64,
    pub failed: u64,
    pub active_cookies: usize,
}

impl SynCookieHandler {
    pub fn new(config: L4Config) -> Self {
        info!("Initializing SYN Cookie Handler");
        Self {
            config,
            active_cookies: HashMap::new(),
            generated_count: AtomicU64::new(0),
            validated_count: AtomicU64::new(0),
            failed_count: AtomicU64::new(0),
        }
    }

    pub async fn start(&self) -> anyhow::Result<()> {
        info!("SYN Cookie Handler started");
        self.start_cleanup_task();
        Ok(())
    }

    pub fn generate_cookie(&mut self, source_ip: IpAddr) -> u32 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;

        let cookie = self.calculate_cookie(source_ip, now);

        self.active_cookies.insert(source_ip, CookieEntry {
            cookie,
            generated_at: std::time::Instant::now(),
        });

        self.generated_count.fetch_add(1, Ordering::Relaxed);
        debug!("Generated SYN cookie for {}: 0x{:x}", source_ip, cookie);

        cookie
    }

    pub fn validate_cookie(&mut self, source_ip: &IpAddr, cookie: u32) -> bool {
        let entry = match self.active_cookies.get(source_ip) {
            Some(entry) => entry,
            None => {
                self.failed_count.fetch_add(1, Ordering::Relaxed);
                return false;
            }
        };

        if entry.cookie != cookie {
            self.failed_count.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        if entry.generated_at.elapsed() > std::time::Duration::from_secs(60) {
            self.failed_count.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        self.validated_count.fetch_add(1, Ordering::Relaxed);
        true
    }

    fn calculate_cookie(&self, source_ip: IpAddr, timestamp: u32) -> u32 {
        let mut hash: u32 = 0x12345678;

        match source_ip {
            IpAddr::V4(v4) => {
                let octets = v4.octets();
                hash ^= octets[0] as u32;
                hash ^= (octets[1] as u32) << 8;
                hash ^= (octets[2] as u32) << 16;
                hash ^= (octets[3] as u32) << 24;
            }
            IpAddr::V6(v6) => {
                let octets = v6.octets();
                for i in 0..16 {
                    hash ^= (octets[i] as u32) << (i % 4) * 8;
                }
            }
        }

        hash ^= timestamp;
        hash.wrapping_mul(0x9e3779b9)
    }

    pub fn get_stats(&self) -> SynCookieStats {
        SynCookieStats {
            generated: self.generated_count.load(Ordering::Relaxed),
            validated: self.validated_count.load(Ordering::Relaxed),
            failed: self.failed_count.load(Ordering::Relaxed),
            active_cookies: self.active_cookies.len(),
        }
    }

    fn start_cleanup_task(&self) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
            loop {
                interval.tick().await;
                debug!("SYN Cookie Handler cleanup task running");
            }
        });
    }
}
