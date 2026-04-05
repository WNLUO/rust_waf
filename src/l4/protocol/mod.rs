pub mod analyzer;
pub mod malformed;
pub mod anomaly;

use crate::config::L4Config;
use log::info;

pub use analyzer::Analyzer;
pub use malformed::MalformedPacketDetector;
pub use anomaly::ProtocolAnomalyDetector;

pub struct MainProtocolAnalyzer {
    config: L4Config,
    malformed_detector: MalformedPacketDetector,
    anomaly_detector: ProtocolAnomalyDetector,
}

impl MainProtocolAnalyzer {
    pub fn new(config: L4Config) -> Self {
        info!("Initializing Protocol Analyzer");
        Self {
            config: config.clone(),
            malformed_detector: MalformedPacketDetector::new(config.clone()),
            anomaly_detector: ProtocolAnomalyDetector::new(config.clone()),
        }
    }

    pub async fn start(&self) -> anyhow::Result<()> {
        info!("Protocol Analyzer started");
        self.malformed_detector.start().await?;
        self.anomaly_detector.start().await?;
        Ok(())
    }

    pub fn detect(&self, packet: &crate::core::PacketInfo) -> Option<crate::core::InspectionResult> {
        // Check for malformed packets
        if let Some(result) = self.malformed_detector.detect(packet) {
            return Some(result);
        }

        // Check for protocol anomalies
        if let Some(result) = self.anomaly_detector.detect(packet) {
            return Some(result);
        }

        None
    }

    pub fn get_stats(&self) -> ProtocolStats {
        ProtocolStats {
            malformed_packets: self.malformed_detector.get_stats(),
            protocol_anomalies: self.anomaly_detector.get_stats(),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ProtocolStats {
    pub malformed_packets: crate::l4::protocol::malformed::MalformedStats,
    pub protocol_anomalies: crate::l4::protocol::anomaly::AnomalyStats,
}
