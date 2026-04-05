use crate::config::L4Config;
use crate::core::{InspectionResult, PacketInfo, WafContext};
use crate::l4::bloom_filter::L4BloomFilterManager;
use crate::l4::connection::ConnectionManager;
use crate::l4::connection::limiter::RATE_LIMIT_BLOCK_DURATION_SECS;
use log::{debug, info};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

pub struct L4Inspector {
    connection_manager: ConnectionManager,
    ddos_enabled: bool,
    advanced_ddos_enabled: bool,
    scan_detection_enabled: bool,
    syn_flood_threshold: usize,
    scan_port_threshold: usize,
    bloom_manager: Option<L4BloomFilterManager>,
    port_stats: Mutex<HashMap<String, PortStats>>,
    ddos_events: AtomicU64,
    scan_events: AtomicU64,
    defense_actions: AtomicU64,
}

impl L4Inspector {
    pub fn new(
        config: L4Config,
        bloom_enabled: bool,
        bloom_false_positive_verification: bool,
    ) -> Self {
        info!("Initializing L4 Inspector with comprehensive detection capabilities");
        info!(
            "Bloom filter enabled: {}, false positive verification: {}",
            bloom_enabled, bloom_false_positive_verification
        );

        let bloom_manager = if bloom_enabled {
            Some(L4BloomFilterManager::new(
                config.clone(),
                bloom_enabled,
                bloom_false_positive_verification,
            ))
        } else {
            None
        };

        Self {
            connection_manager: ConnectionManager::new(config.clone()),
            ddos_enabled: config.ddos_protection_enabled,
            advanced_ddos_enabled: config.advanced_ddos_enabled,
            scan_detection_enabled: config.scan_enabled,
            syn_flood_threshold: config.syn_flood_threshold.max(1),
            scan_port_threshold: Self::scan_port_threshold(&config),
            bloom_manager,
            port_stats: Mutex::new(HashMap::new()),
            ddos_events: AtomicU64::new(0),
            scan_events: AtomicU64::new(0),
            defense_actions: AtomicU64::new(0),
        }
    }

    pub async fn start(&self, _context: &WafContext) -> anyhow::Result<()> {
        info!("Starting L4 Inspector with all subsystems");

        // Start all subsystems
        self.connection_manager.start().await?;

        info!("L4 Inspector all subsystems started successfully");
        Ok(())
    }

    pub fn inspect_packet(&self, packet: &PacketInfo) -> InspectionResult {
        debug!("Inspecting packet at L4 layer");

        let port = packet.dest_port.to_string();

        // Track connection
        self.connection_manager.track(packet);

        if !self.connection_manager.check_rate_limit(&packet.source_ip) {
            self.record_port_event(&port, |stats| {
                stats.increment_block();
            });
            self.defense_actions.fetch_add(1, Ordering::Relaxed);
            return InspectionResult {
                blocked: true,
                reason: "Connection rejected by L4 rate limiter".to_string(),
                layer: crate::core::InspectionLayer::L4,
            };
        }

        // Bloom filter checks
        if let Some(bloom_manager) = &self.bloom_manager {
            if bloom_manager.is_enabled() {
                debug!("Running L4 bloom filter checks");

                // Check IP
                match &packet.source_ip {
                    std::net::IpAddr::V4(ipv4) => {
                        if bloom_manager.check_ipv4(ipv4) {
                            debug!("IPv4 {} matched in bloom filter", ipv4);
                            self.record_port_event(&port, |stats| {
                                stats.increment_block();
                            });
                            self.defense_actions.fetch_add(1, Ordering::Relaxed);
                            return InspectionResult {
                                blocked: true,
                                reason: format!("Blocked by L4 bloom filter: IPv4 {}", ipv4),
                                layer: crate::core::InspectionLayer::L4,
                            };
                        }
                    }
                    std::net::IpAddr::V6(ipv6) => {
                        if bloom_manager.check_ipv6(ipv6) {
                            debug!("IPv6 {} matched in bloom filter", ipv6);
                            self.record_port_event(&port, |stats| {
                                stats.increment_block();
                            });
                            self.defense_actions.fetch_add(1, Ordering::Relaxed);
                            return InspectionResult {
                                blocked: true,
                                reason: format!("Blocked by L4 bloom filter: IPv6 {}", ipv6),
                                layer: crate::core::InspectionLayer::L4,
                            };
                        }
                    }
                }

                // Check IP:Port combination
                if bloom_manager.check_ip_port(&packet.source_ip, packet.source_port) {
                    debug!(
                        "IP:Port {}:{} matched in bloom filter",
                        packet.source_ip, packet.source_port
                    );
                    self.record_port_event(&port, |stats| {
                        stats.increment_block();
                    });
                    self.defense_actions.fetch_add(1, Ordering::Relaxed);
                    return InspectionResult {
                        blocked: true,
                        reason: format!(
                            "Blocked by L4 bloom filter: {}:{}",
                            packet.source_ip, packet.source_port
                        ),
                        layer: crate::core::InspectionLayer::L4,
                    };
                }
            }
        }

        // DDoS detection (simplified)
        if self.ddos_enabled {
            if self.detect_simple_ddos(packet) {
                self.connection_manager.block_ip(
                    &packet.source_ip,
                    "connection flood detected",
                    Duration::from_secs(RATE_LIMIT_BLOCK_DURATION_SECS),
                );
                self.record_port_event(&port, |stats| {
                    stats.increment_block();
                    stats.increment_ddos();
                });
                self.ddos_events.fetch_add(1, Ordering::Relaxed);
                self.defense_actions.fetch_add(1, Ordering::Relaxed);
                return InspectionResult {
                    blocked: true,
                    reason: format!(
                        "DDoS attack detected: {} connections within 1s",
                        self.connection_manager
                            .recent_connection_count(&packet.source_ip, Duration::from_secs(1))
                    ),
                    layer: crate::core::InspectionLayer::L4,
                };
            }
        }

        // Port scan detection (simplified)
        if self.scan_detection_enabled {
            if self.detect_simple_scan(packet) {
                self.connection_manager.block_ip(
                    &packet.source_ip,
                    "port scanning detected",
                    Duration::from_secs(RATE_LIMIT_BLOCK_DURATION_SECS),
                );
                self.record_port_event(&port, |stats| {
                    stats.increment_block();
                    stats.increment_scan();
                });
                self.scan_events.fetch_add(1, Ordering::Relaxed);
                self.defense_actions.fetch_add(1, Ordering::Relaxed);
                return InspectionResult {
                    blocked: true,
                    reason: format!(
                        "Port scanning detected: {} unique destination ports in 30s",
                        self.connection_manager
                            .unique_destination_ports(&packet.source_ip, Duration::from_secs(30))
                    ),
                    layer: crate::core::InspectionLayer::L4,
                };
            }
        }

        // Record successful connection
        self.record_port_event(&port, |stats| {
            stats.increment_connection();
        });

        InspectionResult {
            blocked: false,
            reason: String::new(),
            layer: crate::core::InspectionLayer::L4,
        }
    }

    fn detect_simple_ddos(&self, packet: &PacketInfo) -> bool {
        let burst_count = self
            .connection_manager
            .recent_connection_count(&packet.source_ip, Duration::from_secs(1));
        if burst_count >= self.syn_flood_threshold {
            return true;
        }

        if self.advanced_ddos_enabled {
            let sustained_threshold = self.syn_flood_threshold.saturating_mul(3);
            let sustained_count = self
                .connection_manager
                .recent_connection_count(&packet.source_ip, Duration::from_secs(5));
            if sustained_count >= sustained_threshold.max(self.syn_flood_threshold + 1) {
                return true;
            }
        }

        false
    }

    fn detect_simple_scan(&self, packet: &PacketInfo) -> bool {
        let unique_ports = self
            .connection_manager
            .unique_destination_ports(&packet.source_ip, Duration::from_secs(30));

        unique_ports >= self.scan_port_threshold
    }

    pub fn get_statistics(&self) -> L4Statistics {
        let per_port_stats = self.port_stats.lock().unwrap().clone();
        L4Statistics {
            connections: self.connection_manager.get_stats(),
            ddos_events: self.ddos_events.load(Ordering::Relaxed),
            scan_events: self.scan_events.load(Ordering::Relaxed),
            protocol_anomalies: 0,
            traffic: 0,
            defense_actions: self.defense_actions.load(Ordering::Relaxed),
            bloom_stats: self.bloom_manager.as_ref().map(|m| m.get_statistics()),
            false_positive_stats: self
                .bloom_manager
                .as_ref()
                .map(|m| m.get_false_positive_stats()),
            per_port_stats,
        }
    }

    fn record_port_event<F>(&self, port: &str, update_fn: F)
    where
        F: FnOnce(&mut PortStats),
    {
        let mut stats = self.port_stats.lock().unwrap();
        let port_stats = stats
            .entry(port.to_string())
            .or_insert_with(|| PortStats::new(port.to_string()));
        update_fn(port_stats);
    }

    #[allow(dead_code)]
    pub fn get_bloom_manager_mut(&mut self) -> Option<&mut L4BloomFilterManager> {
        self.bloom_manager.as_mut()
    }

    #[allow(dead_code)]
    pub fn enable_bloom_filter(&mut self, enabled: bool) {
        if let Some(ref mut bloom_manager) = self.bloom_manager {
            bloom_manager.set_enabled(enabled);
        }
    }

    #[allow(dead_code)]
    pub fn set_bloom_false_positive_verification(&mut self, verification: bool) {
        if let Some(ref mut bloom_manager) = self.bloom_manager {
            bloom_manager.set_false_positive_verification(verification);
        }
    }

    pub fn maintenance_tick(&self) {
        self.connection_manager.maintenance_tick();
    }

    fn scan_port_threshold(config: &L4Config) -> usize {
        (config.syn_flood_threshold / 4).clamp(4, 32)
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct PortStats {
    pub port: String,
    pub connections: u64,
    pub blocks: u64,
    pub bytes_processed: u64,
    pub ddos_events: u64,
    pub scan_events: u64,
}

impl PortStats {
    pub fn new(port: String) -> Self {
        Self {
            port,
            connections: 0,
            blocks: 0,
            bytes_processed: 0,
            ddos_events: 0,
            scan_events: 0,
        }
    }

    pub fn increment_connection(&mut self) {
        self.connections += 1;
    }

    pub fn increment_block(&mut self) {
        self.blocks += 1;
    }

    #[allow(dead_code)]
    pub fn add_bytes(&mut self, bytes: usize) {
        self.bytes_processed += bytes as u64;
    }

    pub fn increment_ddos(&mut self) {
        self.ddos_events += 1;
    }

    pub fn increment_scan(&mut self) {
        self.scan_events += 1;
    }
}

#[derive(Debug, Clone)]
pub struct L4Statistics {
    pub connections: crate::l4::connection::ConnectionStats,
    pub ddos_events: u64,
    pub scan_events: u64,
    pub protocol_anomalies: u64,
    pub traffic: u64,
    pub defense_actions: u64,
    #[allow(dead_code)]
    pub bloom_stats: Option<crate::l4::bloom_filter::L4BloomStats>,
    #[allow(dead_code)]
    pub false_positive_stats: Option<crate::l4::bloom_filter::L4FalsePositiveStats>,
    pub per_port_stats: HashMap<String, PortStats>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{InspectionLayer, Protocol};
    use std::net::{IpAddr, Ipv4Addr};

    fn packet(dest_port: u16) -> PacketInfo {
        PacketInfo {
            source_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
            dest_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            source_port: 41_000,
            dest_port,
            protocol: Protocol::TCP,
            timestamp: 0,
        }
    }

    #[test]
    fn detects_connection_floods_from_a_single_source() {
        let inspector = L4Inspector::new(
            L4Config {
                ddos_protection_enabled: true,
                advanced_ddos_enabled: false,
                connection_rate_limit: 1_000,
                syn_flood_threshold: 3,
                scan_enabled: false,
                ..L4Config::default()
            },
            false,
            false,
        );

        assert!(!inspector.inspect_packet(&packet(8080)).blocked);
        assert!(!inspector.inspect_packet(&packet(8080)).blocked);

        let result = inspector.inspect_packet(&packet(8080));
        assert!(result.blocked);
        assert_eq!(result.layer, InspectionLayer::L4);
        assert!(result.reason.contains("DDoS attack detected"));
    }

    #[test]
    fn detects_port_scans_across_multiple_ports() {
        let inspector = L4Inspector::new(
            L4Config {
                ddos_protection_enabled: false,
                connection_rate_limit: 1_000,
                syn_flood_threshold: 16,
                scan_enabled: true,
                ..L4Config::default()
            },
            false,
            false,
        );

        for port in [80, 443, 8080] {
            let result = inspector.inspect_packet(&packet(port));
            assert!(!result.blocked, "unexpected block on port {}", port);
        }

        let result = inspector.inspect_packet(&packet(8443));
        assert!(result.blocked);
        assert_eq!(result.layer, InspectionLayer::L4);
        assert!(result.reason.contains("Port scanning detected"));
    }
}
