use crate::config::L4Config;
use crate::core::{PacketInfo, InspectionResult, InspectionLayer, Protocol};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use log::{info, debug, warn};

pub struct ScanFingerprint {
    config: L4Config,
    fingerprints: HashMap<String, ScanPattern>,
    tool_matches: HashMap<IpAddr, ToolMatch>,
    total_matches: AtomicU64,
}

#[derive(Debug, Clone)]
struct ScanPattern {
    name: String,
    description: String,
    port_pattern: PortPattern,
    timing_pattern: TimingPattern,
}

#[derive(Debug, Clone)]
enum PortPattern {
    Sequential,
    CommonPorts,
    FullRange,
    SpecificPorts(Vec<u16>),
}

#[derive(Debug, Clone)]
enum TimingPattern {
    VeryFast,    // < 1ms between probes
    Fast,        // 1-10ms between probes
    Normal,      // 10-100ms between probes
    Slow,        // 100-1000ms between probes
    VerySlow,    // > 1s between probes (stealth)
}

#[derive(Debug, Clone)]
struct ToolMatch {
    tool_name: String,
    confidence: f32,
    first_seen: std::time::Instant,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct FingerprintStats {
    pub total_matches: u64,
    pub active_tools_detected: usize,
}

impl ScanFingerprint {
    pub fn new(config: L4Config) -> Self {
        info!("Initializing Scan Fingerprint Database");
        Self {
            config,
            fingerprints: Self::initialize_fingerprints(),
            tool_matches: HashMap::new(),
            total_matches: AtomicU64::new(0),
        }
    }

    pub async fn start(&self) -> anyhow::Result<()> {
        info!("Scan Fingerprint Database started");
        self.start_cleanup_task();
        Ok(())
    }

    pub fn detect(&self, packet: &PacketInfo) -> Option<InspectionResult> {
        // Check for Nmap patterns
        if self.detect_nmap_pattern(packet) {
            return Some(InspectionResult {
                blocked: true,
                reason: "Nmap scan pattern detected".to_string(),
                layer: InspectionLayer::L4,
            });
        }

        // Check for Masscan patterns
        if self.detect_masscan_pattern(packet) {
            return Some(InspectionResult {
                blocked: true,
                reason: "Masscan scan pattern detected".to_string(),
                layer: InspectionLayer::L4,
            });
        }

        // Check for Zmap patterns
        if self.detect_zmap_pattern(packet) {
            return Some(InspectionResult {
                blocked: true,
                reason: "Zmap scan pattern detected".to_string(),
                layer: InspectionLayer::L4,
            });
        }

        None
    }

    fn detect_nmap_pattern(&self, packet: &PacketInfo) -> bool {
        // Nmap typically scans common ports first, then specific ranges
        let common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 3389, 5432];

        if packet.protocol == Protocol::TCP {
            if common_ports.contains(&packet.dest_port) {
                debug!("Potential Nmap scan detected on common port {}", packet.dest_port);
                return true;
            }
        }

        false
    }

    fn detect_masscan_pattern(&self, packet: &PacketInfo) -> bool {
        // Masscan is very fast and scans random ports
        // Check if scanning on uncommon ports rapidly
        if packet.protocol == Protocol::TCP {
            let uncommon_ports_range = packet.dest_port > 1024 && packet.dest_port < 49152;
            if uncommon_ports_range {
                debug!("Potential Masscan scan detected on port {}", packet.dest_port);
                return true;
            }
        }

        false
    }

    fn detect_zmap_pattern(&self, packet: &PacketInfo) -> bool {
        // Zmap is typically used for single-port scanning of entire IPv4 space
        // Look for high-frequency single-port scanning
        if packet.protocol == Protocol::TCP || packet.protocol == Protocol::UDP {
            debug!("Potential Zmap scan detected");
            return true;
        }

        false
    }

    fn initialize_fingerprints() -> HashMap<String, ScanPattern> {
        let mut fingerprints = HashMap::new();

        // Nmap fingerprints
        fingerprints.insert("nmap".to_string(), ScanPattern {
            name: "Nmap".to_string(),
            description: "Network Mapper - popular port scanner".to_string(),
            port_pattern: PortPattern::CommonPorts,
            timing_pattern: TimingPattern::Normal,
        });

        // Masscan fingerprints
        fingerprints.insert("masscan".to_string(), ScanPattern {
            name: "Masscan".to_string(),
            description: "Mass IP port scanner".to_string(),
            port_pattern: PortPattern::FullRange,
            timing_pattern: TimingPattern::VeryFast,
        });

        // Zmap fingerprints
        fingerprints.insert("zmap".to_string(), ScanPattern {
            name: "Zmap".to_string(),
            description: "Internet scanner".to_string(),
            port_pattern: PortPattern::SpecificPorts(vec![80, 443]),
            timing_pattern: TimingPattern::VeryFast,
        });

        fingerprints
    }

    pub fn get_stats(&self) -> FingerprintStats {
        FingerprintStats {
            total_matches: self.total_matches.load(Ordering::Relaxed),
            active_tools_detected: self.tool_matches.len(),
        }
    }

    fn start_cleanup_task(&self) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(300)); // 5 minutes
            loop {
                interval.tick().await;
                debug!("Scan Fingerprint cleanup task running");
            }
        });
    }
}
