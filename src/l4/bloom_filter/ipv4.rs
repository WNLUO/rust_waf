use crate::config::L4Config;
use crate::bloom_filter::BloomFilter;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use log::{info, debug};

pub struct IPv4BloomFilter {
    config: L4Config,
    bloom_filter: BloomFilter,
    insert_count: AtomicU64,
    hit_count: AtomicU64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct IPv4BloomStats {
    pub filter_size: usize,
    pub hash_functions: usize,
    pub insert_count: u64,
    pub hit_count: u64,
    pub hit_rate: f64,
}

impl IPv4BloomFilter {
    pub fn new(config: L4Config) -> Self {
        info!("Initializing IPv4 Bloom Filter");

        // Calculate optimal size and hash functions for IPv4 (32 bits)
        let filter_size = 1000000; // 1 million bits ~125KB
        let hash_functions = 3;

        Self {
            config,
            bloom_filter: BloomFilter::new(filter_size, hash_functions),
            insert_count: AtomicU64::new(0),
            hit_count: AtomicU64::new(0),
        }
    }

    pub fn contains(&self, ip: &Ipv4Addr) -> bool {
        let bytes = ip.octets();
        let result = self.bloom_filter.contains(&bytes);

        if result {
            self.hit_count.fetch_add(1, Ordering::Relaxed);
        }

        debug!("IPv4 Bloom filter check for {}: {}", ip, result);
        result
    }

    pub fn insert(&mut self, ip: Ipv4Addr) {
        let bytes = ip.octets();
        self.bloom_filter.insert(&bytes);
        self.insert_count.fetch_add(1, Ordering::Relaxed);
        debug!("IPv4 Bloom filter insert for {}", ip);
    }

    pub fn get_stats(&self) -> IPv4BloomStats {
        let insert_count = self.insert_count.load(Ordering::Relaxed);
        let hit_count = self.hit_count.load(Ordering::Relaxed);
        let hit_rate = if insert_count > 0 {
            hit_count as f64 / insert_count as f64
        } else {
            0.0
        };

        IPv4BloomStats {
            filter_size: self.bloom_filter.size(),
            hash_functions: self.bloom_filter.hash_count(),
            insert_count,
            hit_count,
            hit_rate,
        }
    }
}
