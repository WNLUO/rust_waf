use crate::config::L4Config;
use crate::core::PacketInfo;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use log::{info, debug};

pub struct Analyzer {
    config: L4Config,
    total_bytes: AtomicU64,
    total_packets: AtomicU64,
    protocol_distribution: HashMap<String, u64>,
}

impl Analyzer {
    pub fn new(config: L4Config) -> Self {
        info!("Initializing Traffic Analyzer");
        Self {
            config,
            total_bytes: AtomicU64::new(0),
            total_packets: AtomicU64::new(0),
            protocol_distribution: HashMap::new(),
        }
    }

    pub fn analyze(&self, packet: &PacketInfo) {
        debug!("Analyzing traffic from {}", packet.source_ip);
        self.total_packets.fetch_add(1, Ordering::Relaxed);
    }

    pub fn get_current_load(&self) -> u64 {
        self.total_packets.load(Ordering::Relaxed)
    }

    pub fn get_protocol_distribution(&self) -> &HashMap<String, u64> {
        &self.protocol_distribution
    }
}
