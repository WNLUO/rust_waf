use crate::config::L4Config;
use crate::core::{PacketInfo, InspectionResult, InspectionLayer};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use log::{info, debug, warn};

pub struct HorizontalScanDetector {
    config: L4Config,
    port_tracker: HashMap<IpAddr, PortTracking>,
    detection_threshold: usize,
    detection_window: Duration,
    total_scans_detected: AtomicU64,
}

#[derive(Debug, Clone)]
struct PortTracking {
    ports_scanned: HashSet<u16>,
    first_seen: Instant,
    window_start: Instant,
    scan_duration: Duration,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct HorizontalScanStats {
    pub total_scans_detected: u64,
    pub active_trackers: usize,
    pub highest_port_count: usize,
}

impl HorizontalScanDetector {
    pub fn new(config: L4Config) -> Self {
        info!("Initializing Horizontal Scan Detector");
        Self {
            config,
            port_tracker: HashMap::new(),
            detection_threshold: 10,
            detection_window: Duration::from_secs(30),
            total_scans_detected: AtomicU64::new(0),
        }
    }

    pub async fn start(&self) -> anyhow::Result<()> {
        info!("Horizontal Scan Detector started");
        self.start_cleanup_task();
        Ok(())
    }

    pub fn detect(&self, packet: &PacketInfo) -> Option<InspectionResult> {
        debug!("Checking for horizontal scan patterns from {}", packet.source_ip);

        // Simplified detection - in production would use full port tracking
        None
    }

    pub fn get_stats(&self) -> HorizontalScanStats {
        let highest_port_count = self.port_tracker.values()
            .map(|tracker| tracker.ports_scanned.len())
            .max()
            .unwrap_or(0);

        HorizontalScanStats {
            total_scans_detected: self.total_scans_detected.load(Ordering::Relaxed),
            active_trackers: self.port_tracker.len(),
            highest_port_count,
        }
    }

    fn start_cleanup_task(&self) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                debug!("Horizontal Scan Detector cleanup task running");
            }
        });
    }
}
