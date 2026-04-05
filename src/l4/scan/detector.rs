use crate::config::L4Config;
use crate::core::{PacketInfo, InspectionResult, InspectionLayer};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use log::{info, debug, warn};

use super::{HorizontalScanDetector, VerticalScanDetector, ScanFingerprint};

pub struct Detector {
    config: L4Config,
    horizontal_detector: HorizontalScanDetector,
    vertical_detector: VerticalScanDetector,
    fingerprint: ScanFingerprint,
    scan_threshold: usize,
    scan_window: Duration,
    detected_scanners: HashSet<IpAddr>,
    total_scans_detected: AtomicU64,
}

impl Detector {
    pub fn new(config: L4Config) -> Self {
        info!("Initializing Port Scan Detector");
        Self {
            config: config.clone(),
            horizontal_detector: HorizontalScanDetector::new(config.clone()),
            vertical_detector: VerticalScanDetector::new(config.clone()),
            fingerprint: ScanFingerprint::new(config.clone()),
            scan_threshold: 10, // 10 ports per window
            scan_window: Duration::from_secs(30), // 30 second window
            detected_scanners: HashSet::new(),
            total_scans_detected: AtomicU64::new(0),
        }
    }

    pub async fn start(&self) -> anyhow::Result<()> {
        info!("Port Scan Detector started");
        self.horizontal_detector.start().await?;
        self.vertical_detector.start().await?;
        self.fingerprint.start().await?;
        Ok(())
    }

    pub fn detect(&self, packet: &PacketInfo) -> Option<InspectionResult> {
        debug!("Checking for port scan patterns from {}", packet.source_ip);

        // Delegate to specific detectors
        if let Some(result) = self.horizontal_detector.detect(packet) {
            self.register_scanner(&packet.source_ip);
            return Some(result);
        }

        if let Some(result) = self.vertical_detector.detect(packet) {
            self.register_scanner(&packet.source_ip);
            return Some(result);
        }

        if let Some(result) = self.fingerprint.detect(packet) {
            self.register_scanner(&packet.source_ip);
            return Some(result);
        }

        None
    }

    fn register_scanner(&self, ip: &IpAddr) {
        // Note: In production, this should use internal mutability
        warn!("Detected port scanner: {}", ip);
    }

    pub fn is_scanner(&self, _ip: &IpAddr) -> bool {
        // In production, this would check the actual scanner list
        false
    }

    pub fn unblock_scanner(&self, _ip: &IpAddr) {
        info!("Would unblock scanner (not implemented)");
    }

    pub fn get_all_scanners(&self) -> Vec<IpAddr> {
        self.detected_scanners.iter().cloned().collect()
    }
}

#[derive(Debug, Clone)]
pub struct ScanEvent {
    pub timestamp: Instant,
    pub source_ip: IpAddr,
    pub scan_type: ScanType,
    pub ports_scanned: Vec<u16>,
    pub tool_fingerprint: Option<String>,
}

#[derive(Debug, Clone)]
pub enum ScanType {
    HORIZONTAL,      // Scanning many ports on one host
    VERTICAL,        // Scanning one port on many hosts
    MIXED,           // Combination of both
    STEALTH,         // Slow, stealthy scanning
    FRAGMENTED,      // Fragmented packet scanning
}
