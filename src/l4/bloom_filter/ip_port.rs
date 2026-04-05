use crate::config::L4Config;
use crate::bloom_filter::BloomFilter;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use log::{info, debug};

pub struct IpPortBloomFilter {
    config: L4Config,
    bloom_filter: BloomFilter,
    insert_count: AtomicU64,
    hit_count: AtomicU64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct IpPortBloomStats {
    pub filter_size: usize,
    pub hash_functions: usize,
    pub insert_count: u64,
    pub hit_count: u64,
    pub hit_rate: f64,
}

impl IpPortBloomFilter {
    pub fn new(config: L4Config) -> Self {
        info!("Initializing IP+Port Bloom Filter");

        // Larger filter for IP+Port combinations
        let filter_size = 5000000; // 5 million bits ~625KB
        let hash_functions = 4;

        Self {
            config,
            bloom_filter: BloomFilter::new(filter_size, hash_functions),
            insert_count: AtomicU64::new(0),
            hit_count: AtomicU64::new(0),
        }
    }

    pub fn contains(&self, ip: &IpAddr, port: u16) -> bool {
        let mut data = Vec::new();

        // Add IP bytes
        match ip {
            IpAddr::V4(v4) => data.extend_from_slice(&v4.octets()),
            IpAddr::V6(v6) => data.extend_from_slice(&v6.octets()),
        }

        // Add port bytes
        data.extend_from_slice(&port.to_be_bytes());

        let result = self.bloom_filter.contains(&data);

        if result {
            self.hit_count.fetch_add(1, Ordering::Relaxed);
        }

        debug!("IP+Port Bloom filter check for {}:{}", ip, result);
        result
    }

    pub fn insert(&mut self, ip: IpAddr, port: u16) {
        let mut data = Vec::new();

        // Add IP bytes
        match ip {
            IpAddr::V4(v4) => data.extend_from_slice(&v4.octets()),
            IpAddr::V6(v6) => data.extend_from_slice(&v6.octets()),
        }

        // Add port bytes
        data.extend_from_slice(&port.to_be_bytes());

        self.bloom_filter.insert(&data);
        self.insert_count.fetch_add(1, Ordering::Relaxed);
        debug!("IP+Port Bloom filter insert for {}:{}", ip, port);
    }

    pub fn get_stats(&self) -> IpPortBloomStats {
        let insert_count = self.insert_count.load(Ordering::Relaxed);
        let hit_count = self.hit_count.load(Ordering::Relaxed);
        let hit_rate = if insert_count > 0 {
            hit_count as f64 / insert_count as f64
        } else {
            0.0
        };

        IpPortBloomStats {
            filter_size: self.bloom_filter.size(),
            hash_functions: self.bloom_filter.hash_count(),
            insert_count,
            hit_count,
            hit_rate,
        }
    }
}
