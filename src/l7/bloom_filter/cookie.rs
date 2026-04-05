use crate::bloom_filter::{scaled_bloom_size, BloomFilter};
use crate::config::L7Config;
use log::{debug, info};
use std::sync::atomic::{AtomicU64, Ordering};

pub struct CookieBloomFilter {
    bloom_filter: BloomFilter,
    insert_count: AtomicU64,
    hit_count: AtomicU64,
}

#[allow(dead_code)]
#[derive(Debug, Clone, serde::Serialize)]
pub struct CookieBloomStats {
    pub filter_size: usize,
    pub hash_functions: usize,
    pub insert_count: u64,
    pub hit_count: u64,
    pub hit_rate: f64,
}

impl CookieBloomFilter {
    pub fn new(config: L7Config) -> Self {
        info!("Initializing Cookie Bloom Filter");

        let filter_size = scaled_bloom_size(3_000_000, config.bloom_filter_scale, 131_072);
        let hash_functions = 4;

        Self {
            bloom_filter: BloomFilter::new(filter_size, hash_functions),
            insert_count: AtomicU64::new(0),
            hit_count: AtomicU64::new(0),
        }
    }

    pub fn contains(&self, cookie: &str) -> bool {
        let bytes = cookie.as_bytes();
        let result = self.bloom_filter.contains(bytes);

        if result {
            self.hit_count.fetch_add(1, Ordering::Relaxed);
        }

        debug!("Cookie Bloom filter check for '{}': {}", cookie, result);
        result
    }

    pub fn insert(&mut self, cookie: String) {
        let bytes = cookie.as_bytes();
        self.bloom_filter.insert(bytes);
        self.insert_count.fetch_add(1, Ordering::Relaxed);
        debug!("Cookie Bloom filter insert for '{}'", cookie);
    }

    #[allow(dead_code)]
    pub fn get_stats(&self) -> CookieBloomStats {
        let insert_count = self.insert_count.load(Ordering::Relaxed);
        let hit_count = self.hit_count.load(Ordering::Relaxed);
        let hit_rate = if insert_count > 0 {
            hit_count as f64 / insert_count as f64
        } else {
            0.0
        };

        CookieBloomStats {
            filter_size: self.bloom_filter.size(),
            hash_functions: self.bloom_filter.hash_count(),
            insert_count,
            hit_count,
            hit_rate,
        }
    }
}
