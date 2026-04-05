use crate::config::L4Config;
use std::collections::HashSet;
use std::net::IpAddr;
use log::{info, debug};

pub struct WhitelistManager {
    config: L4Config,
    whitelist: HashSet<IpAddr>,
}

impl WhitelistManager {
    pub fn new(config: L4Config) -> Self {
        info!("Initializing Whitelist Manager");
        Self {
            config,
            whitelist: HashSet::new(),
        }
    }

    pub async fn start(&self) -> anyhow::Result<()> {
        info!("Whitelist Manager started");
        Ok(())
    }

    pub fn is_allowed(&self, ip: &IpAddr) -> bool {
        self.whitelist.contains(ip)
    }

    pub fn add(&mut self, ip: IpAddr) {
        info!("Added IP {} to whitelist", ip);
        self.whitelist.insert(ip);
    }

    pub fn remove(&mut self, ip: &IpAddr) {
        info!("Removed IP {} from whitelist", ip);
        self.whitelist.remove(ip);
    }

    pub fn get_all(&self) -> Vec<IpAddr> {
        self.whitelist.iter().cloned().collect()
    }
}
