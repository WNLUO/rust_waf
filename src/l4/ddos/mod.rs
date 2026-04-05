pub mod detector;
pub mod syn_flood;
pub mod udp_flood;
pub mod icmp_flood;
pub mod syn_cookie;

use crate::config::L4Config;
use log::info;

pub use detector::Detector;
pub use syn_flood::SynFloodDetector;
pub use udp_flood::UdpFloodDetector;
pub use icmp_flood::IcmpFloodDetector;
pub use syn_cookie::SynCookieHandler;

pub struct MainDDoSDetector {
    config: L4Config,
    syn_flood_detector: SynFloodDetector,
    udp_flood_detector: UdpFloodDetector,
    icmp_flood_detector: IcmpFloodDetector,
    syn_cookie_handler: SynCookieHandler,
}

impl MainDDoSDetector {
    pub fn new(config: L4Config) -> Self {
        info!("Initializing DDoS Detector");
        Self {
            config: config.clone(),
            syn_flood_detector: SynFloodDetector::new(config.clone()),
            udp_flood_detector: UdpFloodDetector::new(config.clone()),
            icmp_flood_detector: IcmpFloodDetector::new(config.clone()),
            syn_cookie_handler: SynCookieHandler::new(config.clone()),
        }
    }

    pub async fn start(&self) -> anyhow::Result<()> {
        info!("Starting DDoS Detector");
        self.syn_flood_detector.start().await?;
        self.udp_flood_detector.start().await?;
        self.icmp_flood_detector.start().await?;
        self.syn_cookie_handler.start().await?;
        Ok(())
    }

    pub fn detect(&self, packet: &crate::core::PacketInfo) -> Option<crate::core::InspectionResult> {
        // Check SYN Flood
        if let Some(result) = self.syn_flood_detector.detect(packet) {
            return Some(result);
        }

        // Check UDP Flood
        if let Some(result) = self.udp_flood_detector.detect(packet) {
            return Some(result);
        }

        // Check ICMP Flood
        if let Some(result) = self.icmp_flood_detector.detect(packet) {
            return Some(result);
        }

        None
    }

    pub fn get_stats(&self) -> DDoSStats {
        DDoSStats {
            syn_flood_events: self.syn_flood_detector.get_stats(),
            udp_flood_events: self.udp_flood_detector.get_stats(),
            icmp_flood_events: self.icmp_flood_detector.get_stats(),
            syn_cookie_validations: self.syn_cookie_handler.get_stats(),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DDoSStats {
    pub syn_flood_events: crate::l4::ddos::syn_flood::SynFloodStats,
    pub udp_flood_events: crate::l4::ddos::udp_flood::UdpFloodStats,
    pub icmp_flood_events: crate::l4::ddos::icmp_flood::IcmpFloodStats,
    pub syn_cookie_validations: crate::l4::ddos::syn_cookie::SynCookieStats,
}
