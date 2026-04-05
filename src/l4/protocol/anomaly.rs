use crate::config::L4Config;
use crate::core::{PacketInfo, InspectionResult, InspectionLayer, Protocol};
use std::sync::atomic::{AtomicU64, Ordering};
use log::{info, debug, warn};

pub struct ProtocolAnomalyDetector {
    config: L4Config,
    total_checked: AtomicU64,
    anomaly_count: AtomicU64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct AnomalyStats {
    pub total_checked: u64,
    pub anomalies_detected: u64,
    pub anomaly_rate: f64,
}

impl ProtocolAnomalyDetector {
    pub fn new(config: L4Config) -> Self {
        info!("Initializing Protocol Anomaly Detector");
        Self {
            config,
            total_checked: AtomicU64::new(0),
            anomaly_count: AtomicU64::new(0),
        }
    }

    pub async fn start(&self) -> anyhow::Result<()> {
        info!("Protocol Anomaly Detector started");
        Ok(())
    }

    pub fn detect(&self, packet: &PacketInfo) -> Option<InspectionResult> {
        self.total_checked.fetch_add(1, Ordering::Relaxed);

        if self.has_anomaly(packet) {
            self.anomaly_count.fetch_add(1, Ordering::Relaxed);
            warn!("Protocol anomaly detected from {}", packet.source_ip);

            return Some(InspectionResult {
                blocked: true,
                reason: format!("Protocol anomaly from {}", packet.source_ip),
                layer: InspectionLayer::L4,
            });
        }

        None
    }

    fn has_anomaly(&self, packet: &PacketInfo) -> bool {
        // Check for unusual protocol combinations
        match packet.protocol {
            Protocol::TCP => {
                // TCP to privileged ports from non-standard source
                if packet.dest_port < 1024 && packet.source_port >= 49152 {
                    debug!("Unusual TCP: privileged port {} from ephemeral port {}",
                           packet.dest_port, packet.source_port);
                    return true;
                }
            }
            Protocol::UDP => {
                // UDP on privileged ports
                if packet.dest_port < 1024 && packet.source_port >= 49152 {
                    debug!("Unusual UDP: privileged port {} from ephemeral port {}",
                           packet.dest_port, packet.source_port);
                    return true;
                }
            }
            _ => {}
        }

        false
    }

    pub fn get_stats(&self) -> AnomalyStats {
        let total = self.total_checked.load(Ordering::Relaxed);
        let anomalies = self.anomaly_count.load(Ordering::Relaxed);
        let rate = if total > 0 {
            anomalies as f64 / total as f64
        } else {
            0.0
        };

        AnomalyStats {
            total_checked: total,
            anomalies_detected: anomalies,
            anomaly_rate: rate,
        }
    }
}
