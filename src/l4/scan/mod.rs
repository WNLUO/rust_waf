pub mod detector;
pub mod horizontal;
pub mod vertical;
pub mod fingerprint;

use crate::config::L4Config;
use log::info;

pub use detector::Detector;
pub use horizontal::HorizontalScanDetector;
pub use vertical::VerticalScanDetector;
pub use fingerprint::ScanFingerprint;

pub struct MainScanDetector {
    config: L4Config,
    horizontal_detector: HorizontalScanDetector,
    vertical_detector: VerticalScanDetector,
    fingerprint: ScanFingerprint,
}

impl MainScanDetector {
    pub fn new(config: L4Config) -> Self {
        info!("Initializing Scan Detector");
        Self {
            config: config.clone(),
            horizontal_detector: HorizontalScanDetector::new(config.clone()),
            vertical_detector: VerticalScanDetector::new(config.clone()),
            fingerprint: ScanFingerprint::new(config.clone()),
        }
    }

    pub async fn start(&self) -> anyhow::Result<()> {
        info!("Scan Detector started");
        self.horizontal_detector.start().await?;
        self.vertical_detector.start().await?;
        self.fingerprint.start().await?;
        Ok(())
    }

    pub fn detect(&self, packet: &crate::core::PacketInfo) -> Option<crate::core::InspectionResult> {
        // Check horizontal scan
        if let Some(result) = self.horizontal_detector.detect(packet) {
            return Some(result);
        }

        // Check vertical scan
        if let Some(result) = self.vertical_detector.detect(packet) {
            return Some(result);
        }

        // Check for known scan fingerprints
        if let Some(result) = self.fingerprint.detect(packet) {
            return Some(result);
        }

        None
    }

    pub fn get_stats(&self) -> ScanStats {
        ScanStats {
            horizontal_scans: self.horizontal_detector.get_stats(),
            vertical_scans: self.vertical_detector.get_stats(),
            fingerprint_matches: self.fingerprint.get_stats(),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ScanStats {
    pub horizontal_scans: crate::l4::scan::horizontal::HorizontalScanStats,
    pub vertical_scans: crate::l4::scan::vertical::VerticalScanStats,
    pub fingerprint_matches: crate::l4::scan::fingerprint::FingerprintStats,
}
