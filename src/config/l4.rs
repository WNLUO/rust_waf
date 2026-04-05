use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L4Config {
    pub ddos_protection_enabled: bool,
    pub advanced_ddos_enabled: bool,
    pub connection_rate_limit: usize,
    pub syn_flood_threshold: usize,
    pub scan_enabled: bool,
    pub max_tracked_ips: usize,
    pub max_blocked_ips: usize,
    pub state_ttl_secs: u64,
}

impl Default for L4Config {
    fn default() -> Self {
        Self {
            ddos_protection_enabled: true,
            advanced_ddos_enabled: false,
            connection_rate_limit: 100,
            syn_flood_threshold: 50,
            scan_enabled: false,
            max_tracked_ips: 4096,
            max_blocked_ips: 1024,
            state_ttl_secs: 300,
        }
    }
}
