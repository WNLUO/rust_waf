use crate::config::L4Config;
use crate::core::{PacketInfo, Protocol};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use log::{info, debug};

pub struct TrafficStatistics {
    config: L4Config,
    total_packets: AtomicU64,
    total_bytes: AtomicU64,
    protocol_stats: HashMap<String, ProtocolStats>,
    ip_stats: HashMap<String, IpStats>,
}

#[derive(Debug, Clone)]
struct ProtocolStats {
    packet_count: u64,
    byte_count: u64,
}

#[derive(Debug, Clone)]
struct IpStats {
    packet_count: u64,
    byte_count: u64,
    last_seen: std::time::Instant,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct TrafficStatisticsStats {
    pub total_packets: u64,
    pub total_bytes: u64,
    pub protocol_distribution: HashMap<String, u64>,
    pub top_talkers: Vec<(String, u64)>,
}

impl TrafficStatistics {
    pub fn new(config: L4Config) -> Self {
        info!("Initializing Traffic Statistics");
        Self {
            config,
            total_packets: AtomicU64::new(0),
            total_bytes: AtomicU64::new(0),
            protocol_stats: HashMap::new(),
            ip_stats: HashMap::new(),
        }
    }

    pub async fn start(&self) -> anyhow::Result<()> {
        info!("Traffic Statistics started");
        Ok(())
    }

    pub fn record(&mut self, packet: &PacketInfo) {
        self.total_packets.fetch_add(1, Ordering::Relaxed);

        // Update protocol stats (using String key to avoid Hash trait issues)
        let protocol_name = format!("{:?}", packet.protocol);
        let proto_stats = self.protocol_stats
            .entry(protocol_name.clone())
            .or_insert_with(|| ProtocolStats {
                packet_count: 0,
                byte_count: 0,
            });
        proto_stats.packet_count += 1;

        // Update IP stats
        let ip_key = packet.source_ip.to_string();
        let ip_stats = self.ip_stats
            .entry(ip_key)
            .or_insert_with(|| IpStats {
                packet_count: 0,
                byte_count: 0,
                last_seen: std::time::Instant::now(),
            });
        ip_stats.packet_count += 1;
        ip_stats.last_seen = std::time::Instant::now();
    }

    pub fn get_stats(&self) -> TrafficStatisticsStats {
        let total_packets = self.total_packets.load(Ordering::Relaxed);
        let total_bytes = self.total_bytes.load(Ordering::Relaxed);

        let protocol_distribution: HashMap<String, u64> = self.protocol_stats
            .iter()
            .map(|(proto, stats)| (proto.clone(), stats.packet_count))
            .collect();

        let mut top_talkers: Vec<(String, u64)> = self.ip_stats
            .iter()
            .map(|(ip, stats)| (ip.clone(), stats.packet_count))
            .collect();
        top_talkers.sort_by(|a, b| b.1.cmp(&a.1));
        top_talkers.truncate(10);

        TrafficStatisticsStats {
            total_packets,
            total_bytes,
            protocol_distribution,
            top_talkers,
        }
    }
}
