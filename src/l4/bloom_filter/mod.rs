pub mod ip_port;
pub mod ipv4;
pub mod ipv6;

pub use ip_port::IpPortBloomFilter;
pub use ipv4::IPv4BloomFilter;
pub use ipv6::IPv6BloomFilter;

use crate::config::L4Config;
use log::info;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub struct L4BloomFilterManager {
    ipv4_filter: IPv4BloomFilter,
    ipv6_filter: IPv6BloomFilter,
    ip_port_filter: IpPortBloomFilter,
    enabled: bool,
    false_positive_verification: bool,
    exact_set_ipv4: std::collections::HashSet<std::net::Ipv4Addr>,
    exact_set_ipv6: std::collections::HashSet<std::net::Ipv6Addr>,
    exact_set_ip_port: std::collections::HashSet<(std::net::IpAddr, u16)>,
}

impl L4BloomFilterManager {
    pub fn new(config: L4Config, enabled: bool, false_positive_verification: bool) -> Self {
        info!(
            "Initializing L4 Bloom Filter Manager (enabled: {}, false_positive_verification: {})",
            enabled, false_positive_verification
        );
        let mut manager = Self {
            ipv4_filter: IPv4BloomFilter::new(config.clone()),
            ipv6_filter: IPv6BloomFilter::new(config.clone()),
            ip_port_filter: IpPortBloomFilter::new(config),
            enabled,
            false_positive_verification,
            exact_set_ipv4: std::collections::HashSet::new(),
            exact_set_ipv6: std::collections::HashSet::new(),
            exact_set_ip_port: std::collections::HashSet::new(),
        };
        manager.preload_defaults();
        manager
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    #[allow(dead_code)]
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
        log::info!("L4 Bloom filter enabled: {}", enabled);
    }

    #[allow(dead_code)]
    pub fn set_false_positive_verification(&mut self, verification: bool) {
        self.false_positive_verification = verification;
        log::info!(
            "L4 Bloom filter false positive verification: {}",
            verification
        );
    }

    pub fn check_ipv4(&self, ip: &std::net::Ipv4Addr) -> bool {
        if !self.enabled {
            return false;
        }

        let bloom_result = self.ipv4_filter.contains(ip);

        if !bloom_result {
            return false;
        }

        if self.false_positive_verification {
            let exact_result = self.exact_set_ipv4.contains(ip);
            log::debug!(
                "IPv4 Bloom filter hit for {}, exact verification: {}",
                ip,
                exact_result
            );
            exact_result
        } else {
            bloom_result
        }
    }

    pub fn add_ipv4(&mut self, ip: std::net::Ipv4Addr) {
        self.ipv4_filter.insert(ip);
        if self.false_positive_verification {
            self.exact_set_ipv4.insert(ip);
        }
    }

    pub fn check_ipv6(&self, ip: &std::net::Ipv6Addr) -> bool {
        if !self.enabled {
            return false;
        }

        let bloom_result = self.ipv6_filter.contains(ip);

        if !bloom_result {
            return false;
        }

        if self.false_positive_verification {
            let exact_result = self.exact_set_ipv6.contains(ip);
            log::debug!(
                "IPv6 Bloom filter hit for {}, exact verification: {}",
                ip,
                exact_result
            );
            exact_result
        } else {
            bloom_result
        }
    }

    pub fn add_ipv6(&mut self, ip: std::net::Ipv6Addr) {
        self.ipv6_filter.insert(ip);
        if self.false_positive_verification {
            self.exact_set_ipv6.insert(ip);
        }
    }

    pub fn check_ip_port(&self, ip: &std::net::IpAddr, port: u16) -> bool {
        if !self.enabled {
            return false;
        }

        let bloom_result = self.ip_port_filter.contains(ip, port);

        if !bloom_result {
            return false;
        }

        if self.false_positive_verification {
            let key = (ip.clone(), port);
            let exact_result = self.exact_set_ip_port.contains(&key);
            log::debug!(
                "IP:Port Bloom filter hit for {}:{}, exact verification: {}",
                ip,
                port,
                exact_result
            );
            exact_result
        } else {
            bloom_result
        }
    }

    pub fn add_ip_port(&mut self, ip: std::net::IpAddr, port: u16) {
        self.ip_port_filter.insert(ip, port);
        if self.false_positive_verification {
            self.exact_set_ip_port.insert((ip, port));
        }
    }

    fn preload_defaults(&mut self) {
        let sample_ipv4 = [
            Ipv4Addr::new(192, 0, 2, 1),
            Ipv4Addr::new(198, 51, 100, 2),
            Ipv4Addr::new(203, 0, 113, 3),
        ];
        for ip in sample_ipv4 {
            self.add_ipv4(ip);
        }

        let sample_ipv6 = [
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2),
        ];
        for ip in sample_ipv6 {
            self.add_ipv6(ip);
        }

        let sample_ip_port = [
            (IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)), 8080),
            (IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)), 22),
        ];
        for (ip, port) in sample_ip_port {
            self.add_ip_port(ip, port);
        }
    }

    pub fn get_statistics(&self) -> L4BloomStats {
        L4BloomStats {
            ipv4_filter: self.ipv4_filter.get_stats(),
            ipv6_filter: self.ipv6_filter.get_stats(),
            ip_port_filter: self.ip_port_filter.get_stats(),
            enabled: self.enabled,
            false_positive_verification: self.false_positive_verification,
        }
    }

    pub fn get_false_positive_stats(&self) -> L4FalsePositiveStats {
        L4FalsePositiveStats {
            ipv4_exact_size: self.exact_set_ipv4.len(),
            ipv6_exact_size: self.exact_set_ipv6.len(),
            ip_port_exact_size: self.exact_set_ip_port.len(),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct L4BloomStats {
    pub ipv4_filter: ipv4::IPv4BloomStats,
    pub ipv6_filter: ipv6::IPv6BloomStats,
    pub ip_port_filter: ip_port::IpPortBloomStats,
    pub enabled: bool,
    pub false_positive_verification: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct L4FalsePositiveStats {
    pub ipv4_exact_size: usize,
    pub ipv6_exact_size: usize,
    pub ip_port_exact_size: usize,
}
