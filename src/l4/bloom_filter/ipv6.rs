use crate::config::L4Config;
use crate::bloom_filter::BloomFilter;
use std::net::Ipv6Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use log::{info, debug};

pub struct IPv6BloomFilter {
    config: L4Config,
    bloom_filter: BloomFilter,
    insert_count: AtomicU64,
    hit_count: AtomicU64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct IPv6BloomStats {
    pub filter_size: usize,
    pub hash_functions: usize,
    pub insert_count: u64,
    pub hit_count: u64,
    pub hit_rate: f64,
}

impl IPv6BloomFilter {
    pub fn new(config: L4Config) -> Self {
        info!("Initializing IPv6 Bloom Filter");

        // Larger filter for IPv6 (128 bits)
        let filter_size = 2000000; // 2 million bits ~250KB
        let hash_functions = 5;

        Self {
            config,
            bloom_filter: BloomFilter::new(filter_size, hash_functions),
            insert_count: AtomicU64::new(0),
            hit_count: AtomicU64::new(0),
        }
    }

    pub fn contains(&self, ip: &Ipv6Addr) -> bool {
        let bytes = ip.octets();
        let result = self.bloom_filter.contains(&bytes);

        if result {
            self.hit_count.fetch_add(1, Ordering::Relaxed);
        }

        debug!("IPv6 Bloom filter check for {}: {}", ip, result);
        result
    }

    pub fn insert(&mut self, ip: Ipv6Addr) {
        let bytes = ip.octets();
        self.bloom_filter.insert(&bytes);
        self.insert_count.fetch_add(1, Ordering::Relaxed);
        debug!("IPv6 Bloom filter insert for {}", ip);
    }

    pub fn get_stats(&self) -> IPv6BloomStats {
        let insert_count = self.insert_count.load(Ordering::Relaxed);
        let hit_count = self.hit_count.load(Ordering::Relaxed);
        let hit_rate = if insert_count > 0 {
            hit_count as f64 / insert_count as f64
        } else {
            0.0
        };

        IPv6BloomStats {
            filter_size: self.bloom_filter.size(),
            hash_functions: self.bloom_filter.hash_count(),
            insert_count,
            hit_count,
            hit_rate,
        }
    }
}
