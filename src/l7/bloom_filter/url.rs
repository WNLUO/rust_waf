use crate::config::L7Config;
use crate::bloom_filter::BloomFilter;
use std::sync::atomic::{AtomicU64, Ordering};
use log::{info, debug};

pub struct UrlBloomFilter {
    config: L7Config,
    bloom_filter: BloomFilter,
    insert_count: AtomicU64,
    hit_count: AtomicU64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct UrlBloomStats {
    pub filter_size: usize,
    pub hash_functions: usize,
    pub insert_count: u64,
    pub hit_count: u64,
    pub hit_rate: f64,
}

impl UrlBloomFilter {
    pub fn new(config: L7Config) -> Self {
        info!("Initializing URL Bloom Filter");

        // Larger filter for URLs (longer strings)
        let filter_size = 8000000; // 8 million bits ~1MB
        let hash_functions = 5;

        Self {
            config,
            bloom_filter: BloomFilter::new(filter_size, hash_functions),
            insert_count: AtomicU64::new(0),
            hit_count: AtomicU64::new(0),
        }
    }

    pub fn contains(&self, url: &str) -> bool {
        let bytes = url.as_bytes();
        let result = self.bloom_filter.contains(bytes);

        if result {
            self.hit_count.fetch_add(1, Ordering::Relaxed);
        }

        debug!("URL Bloom filter check for '{}': {}", url, result);
        result
    }

    pub fn insert(&mut self, url: String) {
        let bytes = url.as_bytes();
        self.bloom_filter.insert(bytes);
        self.insert_count.fetch_add(1, Ordering::Relaxed);
        debug!("URL Bloom filter insert for '{}'", url);
    }

    pub fn get_stats(&self) -> UrlBloomStats {
        let insert_count = self.insert_count.load(Ordering::Relaxed);
        let hit_count = self.hit_count.load(Ordering::Relaxed);
        let hit_rate = if insert_count > 0 {
            hit_count as f64 / insert_count as f64
        } else {
            0.0
        };

        UrlBloomStats {
            filter_size: self.bloom_filter.size(),
            hash_functions: self.bloom_filter.hash_count(),
            insert_count,
            hit_count,
            hit_rate,
        }
    }
}
