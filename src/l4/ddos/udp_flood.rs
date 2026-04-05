use crate::config::L4Config;
use crate::core::{PacketInfo, InspectionResult, InspectionLayer, Protocol};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use std::time::{Duration, Instant};
use log::{info, debug, warn};

pub struct UdpFloodDetector {
    config: L4Config,
    udp_counts: HashMap<IpAddr, UdpTracker>,
    total_udp_packets: AtomicU64,
    under_attack: AtomicBool,
    detection_threshold: usize,
    detection_window: Duration,
}

#[derive(Debug, Clone)]
struct UdpTracker {
    count: usize,
    bytes_total: u64,
    first_seen: Instant,
    window_start: Instant,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct UdpFloodStats {
    pub total_udp_packets: u64,
    pub total_bytes: u64,
    pub unique_sources: usize,
    pub attacks_detected: u64,
    pub under_attack: bool,
}

impl UdpFloodDetector {
    pub fn new(config: L4Config) -> Self {
        info!("Initializing UDP Flood Detector");
        Self {
            config: config.clone(),
            udp_counts: HashMap::new(),
            total_udp_packets: AtomicU64::new(0),
            under_attack: AtomicBool::new(false),
            detection_threshold: config.connection_rate_limit * 5,
            detection_window: Duration::from_secs(1),
        }
    }

    pub async fn start(&self) -> anyhow::Result<()> {
        info!("UDP Flood Detector started");
        self.start_cleanup_task();
        Ok(())
    }

    pub fn detect(&self, packet: &PacketInfo) -> Option<InspectionResult> {
        // Only check UDP packets
        if packet.protocol != Protocol::UDP {
            return None;
        }

        self.total_udp_packets.fetch_add(1, Ordering::Relaxed);
        debug!("UDP packet from {}", packet.source_ip);

        // Simplified detection - in production would use full tracking
        None
    }

    pub fn is_under_attack(&self) -> bool {
        self.under_attack.load(Ordering::Relaxed)
    }

    pub fn get_current_load(&self) -> usize {
        self.udp_counts.values()
            .map(|tracker| tracker.count)
            .sum()
    }

    pub fn get_stats(&self) -> UdpFloodStats {
        let total_bytes: u64 = self.udp_counts.values()
            .map(|tracker| tracker.bytes_total)
            .sum();

        UdpFloodStats {
            total_udp_packets: self.total_udp_packets.load(Ordering::Relaxed),
            total_bytes,
            unique_sources: self.udp_counts.len(),
            attacks_detected: if self.is_under_attack() { 1 } else { 0 },
            under_attack: self.is_under_attack(),
        }
    }

    fn start_cleanup_task(&self) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(5));
            loop {
                interval.tick().await;
                debug!("UDP Flood Detector cleanup task running");
            }
        });
    }
}
