use crate::config::L4Config;
use crate::core::{PacketInfo, InspectionResult, InspectionLayer, Protocol};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use std::time::{Duration, Instant};
use log::{info, debug, warn};

pub struct IcmpFloodDetector {
    config: L4Config,
    icmp_counts: HashMap<IpAddr, IcmpTracker>,
    total_icmp_packets: AtomicU64,
    under_attack: AtomicBool,
    detection_threshold: usize,
    detection_window: Duration,
}

#[derive(Debug, Clone)]
struct IcmpTracker {
    count: usize,
    first_seen: Instant,
    window_start: Instant,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct IcmpFloodStats {
    pub total_icmp_packets: u64,
    pub unique_sources: usize,
    pub attacks_detected: u64,
    pub under_attack: bool,
}

impl IcmpFloodDetector {
    pub fn new(config: L4Config) -> Self {
        info!("Initializing ICMP Flood Detector");
        Self {
            config: config.clone(),
            icmp_counts: HashMap::new(),
            total_icmp_packets: AtomicU64::new(0),
            under_attack: AtomicBool::new(false),
            detection_threshold: config.connection_rate_limit * 3,
            detection_window: Duration::from_secs(1),
        }
    }

    pub async fn start(&self) -> anyhow::Result<()> {
        info!("ICMP Flood Detector started");
        self.start_cleanup_task();
        Ok(())
    }

    pub fn detect(&self, packet: &PacketInfo) -> Option<InspectionResult> {
        // Only check ICMP packets
        if packet.protocol != Protocol::ICMP {
            return None;
        }

        self.total_icmp_packets.fetch_add(1, Ordering::Relaxed);
        debug!("ICMP packet from {}", packet.source_ip);

        // Simplified detection - in production would use full tracking
        None
    }

    pub fn is_under_attack(&self) -> bool {
        self.under_attack.load(Ordering::Relaxed)
    }

    pub fn get_current_load(&self) -> usize {
        self.icmp_counts.values()
            .map(|tracker| tracker.count)
            .sum()
    }

    pub fn get_stats(&self) -> IcmpFloodStats {
        IcmpFloodStats {
            total_icmp_packets: self.total_icmp_packets.load(Ordering::Relaxed),
            unique_sources: self.icmp_counts.len(),
            attacks_detected: if self.is_under_attack() { 1 } else { 0 },
            under_attack: self.is_under_attack(),
        }
    }

    fn start_cleanup_task(&self) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(5));
            loop {
                interval.tick().await;
                debug!("ICMP Flood Detector cleanup task running");
            }
        });
    }
}
