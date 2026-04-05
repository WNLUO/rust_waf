use crate::config::L4Config;
use crate::core::{PacketInfo, InspectionResult, InspectionLayer};
use log::{info, debug, warn};

use super::{SynFloodDetector, UdpFloodDetector, IcmpFloodDetector};

pub struct Detector {
    config: L4Config,
    syn_flood: SynFloodDetector,
    udp_flood: UdpFloodDetector,
    icmp_flood: IcmpFloodDetector,
    detection_threshold: usize,
    detection_window: std::time::Duration,
}

impl Detector {
    pub fn new(config: L4Config) -> Self {
        info!("Initializing DDoS Detector");
        Self {
            config: config.clone(),
            syn_flood: SynFloodDetector::new(config.clone()),
            udp_flood: UdpFloodDetector::new(config.clone()),
            icmp_flood: IcmpFloodDetector::new(config.clone()),
            detection_threshold: config.syn_flood_threshold * 2, // More sensitive for general detection
            detection_window: std::time::Duration::from_secs(5),
        }
    }

    pub async fn start(&self) -> anyhow::Result<()> {
        info!("DDoS Detector started");
        self.syn_flood.start().await?;
        self.udp_flood.start().await?;
        self.icmp_flood.start().await?;
        Ok(())
    }

    pub fn detect(&self, packet: &PacketInfo) -> Option<InspectionResult> {
        debug!("Checking for DDoS patterns in packet from {}", packet.source_ip);

        // Delegate to specific detectors
        if let Some(result) = self.syn_flood.detect(packet) {
            return Some(result);
        }

        if let Some(result) = self.udp_flood.detect(packet) {
            return Some(result);
        }

        if let Some(result) = self.icmp_flood.detect(packet) {
            return Some(result);
        }

        None
    }

    pub fn is_ddos_detected(&self) -> bool {
        self.syn_flood.is_under_attack() ||
        self.udp_flood.is_under_attack() ||
        self.icmp_flood.is_under_attack()
    }

    pub fn get_current_load(&self) -> usize {
        self.syn_flood.get_current_load() +
        self.udp_flood.get_current_load() +
        self.icmp_flood.get_current_load()
    }
}

#[derive(Debug, Clone)]
pub struct DDoSEvent {
    pub timestamp: std::time::Instant,
    pub attack_type: DDoSAttackType,
    pub source_ip: std::net::IpAddr,
    pub packet_count: usize,
    pub severity: DDoSSeverity,
}

#[derive(Debug, Clone)]
pub enum DDoSAttackType {
    SYN_FLOOD,
    UDP_FLOOD,
    ICMP_FLOOD,
    MIXED_ATTACK,
}

#[derive(Debug, Clone)]
pub enum DDoSSeverity {
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL,
}
