use crate::config::L4Config;
use std::collections::HashSet;
use std::net::IpAddr;
use log::{info, debug};

pub struct BlacklistManager {
    config: L4Config,
    blacklist: HashSet<IpAddr>,
}

impl BlacklistManager {
    pub fn new(config: L4Config) -> Self {
        info!("Initializing Blacklist Manager");
        Self {
            config,
            blacklist: HashSet::new(),
        }
    }

    pub async fn start(&self) -> anyhow::Result<()> {
        info!("Blacklist Manager started");
        Ok(())
    }

    pub fn is_blocked(&self, ip: &IpAddr) -> bool {
        self.blacklist.contains(ip)
    }

    pub fn add(&mut self, ip: IpAddr) {
        info!("Added IP {} to blacklist", ip);
        self.blacklist.insert(ip);
    }

    pub fn remove(&mut self, ip: &IpAddr) {
        info!("Removed IP {} from blacklist", ip);
        self.blacklist.remove(ip);
    }

    pub fn get_all(&self) -> Vec<IpAddr> {
        self.blacklist.iter().cloned().collect()
    }
}
