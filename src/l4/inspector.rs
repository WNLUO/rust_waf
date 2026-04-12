use crate::config::L4Config;
use crate::core::{InspectionLayer, InspectionResult, PacketInfo, WafContext};
use crate::l4::behavior::{FeedbackSource, L4BehaviorEngine, L4BehaviorSnapshot};
use crate::l4::bloom_filter::L4BloomFilterManager;
use crate::l4::connection::limiter::RATE_LIMIT_BLOCK_DURATION_SECS;
use crate::l4::connection::{ConnectionManager, RateLimitDecision};
use crate::protocol::UnifiedHttpRequest;
use log::{debug, info};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

pub struct L4Inspector {
    connection_manager: ConnectionManager,
    behavior_engine: L4BehaviorEngine,
    ddos_enabled: bool,
    advanced_ddos_enabled: bool,
    syn_flood_threshold: usize,
    bloom_manager: Option<L4BloomFilterManager>,
    port_stats: Mutex<HashMap<String, PortStats>>,
    ddos_events: AtomicU64,
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
            behavior_engine: L4BehaviorEngine::new(&config),
            ddos_enabled: config.ddos_protection_enabled,
            advanced_ddos_enabled: config.advanced_ddos_enabled,
            syn_flood_threshold: config.syn_flood_threshold.max(1),
            bloom_manager,
            port_stats: Mutex::new(HashMap::new()),
            ddos_events: AtomicU64::new(0),
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

        match self.connection_manager.check_rate_limit(&packet.source_ip) {
            RateLimitDecision::Allowed => {}
            RateLimitDecision::Rejected => {
                self.record_port_event(&port, |stats| {
                    stats.increment_block();
                });
                self.defense_actions.fetch_add(1, Ordering::Relaxed);
                return InspectionResult::block(
                    InspectionLayer::L4,
                    "Connection rejected by L4 rate limiter",
                );
            }
            RateLimitDecision::RejectedAndBlocked => {
                self.record_port_event(&port, |stats| {
                    stats.increment_block();
                });
                self.defense_actions.fetch_add(1, Ordering::Relaxed);
                return InspectionResult::block_and_persist_ip(
                    InspectionLayer::L4,
                    "Connection rejected by L4 rate limiter",
                );
            }
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
                            return InspectionResult::block(
                                InspectionLayer::L4,
                                format!("Blocked by L4 bloom filter: IPv4 {}", ipv4),
                            );
                        }
                    }
                    std::net::IpAddr::V6(ipv6) => {
                        if bloom_manager.check_ipv6(ipv6) {
                            debug!("IPv6 {} matched in bloom filter", ipv6);
                            self.record_port_event(&port, |stats| {
                                stats.increment_block();
                            });
                            self.defense_actions.fetch_add(1, Ordering::Relaxed);
                            return InspectionResult::block(
                                InspectionLayer::L4,
                                format!("Blocked by L4 bloom filter: IPv6 {}", ipv6),
                            );
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
                    return InspectionResult::block(
                        InspectionLayer::L4,
                        format!(
                            "Blocked by L4 bloom filter: {}:{}",
                            packet.source_ip, packet.source_port
                        ),
                    );
                }
            }
        }

        // DDoS detection (simplified)
        if self.ddos_enabled {
            if self.detect_simple_ddos(packet) {
                let blocked = self.connection_manager.block_ip(
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
                let reason = format!(
                    "DDoS attack detected: {} connections within 1s",
                    self.connection_manager
                        .recent_connection_count(&packet.source_ip, Duration::from_secs(1))
                );
                return if blocked {
                    InspectionResult::block_and_persist_ip(InspectionLayer::L4, reason)
                } else {
                    InspectionResult::block(InspectionLayer::L4, reason)
                };
            }
        }

        // Record successful connection
        self.record_port_event(&port, |stats| {
            stats.increment_connection();
        });

        InspectionResult::allow(InspectionLayer::L4)
    }

    pub fn observe_connection_open(
        &self,
        connection_id: String,
        packet: &PacketInfo,
        authority: Option<&str>,
        alpn: Option<&str>,
        transport: &str,
        protocol_hint: &str,
    ) -> crate::l4::behavior::BucketKey {
        self.behavior_engine.observe_connection_open(
            connection_id,
            packet,
            authority,
            alpn,
            transport,
            protocol_hint,
        )
    }

    pub fn observe_connection_close(
        &self,
        key: &crate::l4::behavior::BucketKey,
        connection_id: &str,
        opened_at: std::time::Instant,
    ) {
        self.behavior_engine
            .observe_connection_close(key, connection_id, opened_at);
    }

    pub fn apply_request_policy(
        &self,
        packet: &PacketInfo,
        request: &mut UnifiedHttpRequest,
    ) -> crate::l4::behavior::L4AdaptivePolicy {
        self.behavior_engine.apply_request_policy(packet, request)
    }

    pub fn connection_admission_policy(
        &self,
        key: &crate::l4::behavior::BucketKey,
    ) -> crate::l4::behavior::L4AdaptivePolicy {
        self.behavior_engine.connection_admission_for_key(key)
    }

    pub fn coarse_connection_admission_policy(
        &self,
        peer_ip: std::net::IpAddr,
        transport: &str,
    ) -> crate::l4::behavior::L4AdaptivePolicy {
        self.behavior_engine
            .pre_admission_policy(peer_ip, transport)
    }

    pub fn record_l7_feedback(
        &self,
        packet: &PacketInfo,
        request: &UnifiedHttpRequest,
        source: FeedbackSource,
    ) {
        self.behavior_engine
            .observe_feedback(packet, request, source);
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

    pub fn get_statistics(&self) -> L4Statistics {
        let per_port_stats = self.port_stats.lock().unwrap().clone();
        let connection_stats = self.connection_manager.get_stats();
        L4Statistics {
            behavior: self.behavior_engine.snapshot(
                connection_stats.blocked_connections,
                connection_stats.active_connections,
            ),
            connections: connection_stats,
            ddos_events: self.ddos_events.load(Ordering::Relaxed),
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

    pub fn unblock_ip(&self, ip: &std::net::IpAddr) -> bool {
        self.connection_manager.unblock_ip(ip)
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct PortStats {
    pub port: String,
    pub connections: u64,
    pub blocks: u64,
    pub bytes_processed: u64,
    pub ddos_events: u64,
}

impl PortStats {
    pub fn new(port: String) -> Self {
        Self {
            port,
            connections: 0,
            blocks: 0,
            bytes_processed: 0,
            ddos_events: 0,
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
}

#[derive(Debug, Clone)]
pub struct L4Statistics {
    pub behavior: L4BehaviorSnapshot,
    pub connections: crate::l4::connection::ConnectionStats,
    pub ddos_events: u64,
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
}
