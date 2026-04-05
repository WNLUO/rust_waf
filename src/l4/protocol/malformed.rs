use crate::config::L4Config;
use crate::core::{PacketInfo, InspectionResult, InspectionLayer};
use std::sync::atomic::{AtomicU64, Ordering};
use log::{info, debug, warn};

pub struct MalformedPacketDetector {
    config: L4Config,
    total_checked: AtomicU64,
    malformed_count: AtomicU64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct MalformedStats {
    pub total_checked: u64,
    pub malformed_packets: u64,
    pub malformed_rate: f64,
}

impl MalformedPacketDetector {
    pub fn new(config: L4Config) -> Self {
        info!("Initializing Malformed Packet Detector");
        Self {
            config,
            total_checked: AtomicU64::new(0),
            malformed_count: AtomicU64::new(0),
        }
    }

    pub async fn start(&self) -> anyhow::Result<()> {
        info!("Malformed Packet Detector started");
        Ok(())
    }

    pub fn detect(&self, packet: &PacketInfo) -> Option<InspectionResult> {
        self.total_checked.fetch_add(1, Ordering::Relaxed);

        if self.is_malformed(packet) {
            self.malformed_count.fetch_add(1, Ordering::Relaxed);
            warn!("Malformed packet detected from {}", packet.source_ip);

            return Some(InspectionResult {
                blocked: true,
                reason: format!("Malformed packet from {}", packet.source_ip),
                layer: InspectionLayer::L4,
            });
        }

        None
    }

    fn is_malformed(&self, packet: &PacketInfo) -> bool {
        // Check for invalid port numbers
        if packet.source_port == 0 || packet.dest_port == 0 {
            return true;
        }

        // Check for invalid port numbers > 65535
        if packet.source_port > 65535 || packet.dest_port > 65535 {
            return true;
        }

        false
    }

    pub fn get_stats(&self) -> MalformedStats {
        let total = self.total_checked.load(Ordering::Relaxed);
        let malformed = self.malformed_count.load(Ordering::Relaxed);
        let rate = if total > 0 {
            malformed as f64 / total as f64
        } else {
            0.0
        };

        MalformedStats {
            total_checked: total,
            malformed_packets: malformed,
            malformed_rate: rate,
        }
    }
}
