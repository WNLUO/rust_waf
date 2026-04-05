use crate::bloom_filter::{scaled_bloom_size, BloomFilter};
use crate::config::L7Config;
use log::{debug, info};
use std::sync::atomic::{AtomicU64, Ordering};

pub struct HttpMethodBloomFilter {
    bloom_filter: BloomFilter,
    insert_count: AtomicU64,
    hit_count: AtomicU64,
}

#[allow(dead_code)]
#[derive(Debug, Clone, serde::Serialize)]
pub struct HttpMethodBloomStats {
    pub filter_size: usize,
    pub hash_functions: usize,
    pub insert_count: u64,
    pub hit_count: u64,
    pub hit_rate: f64,
}

impl HttpMethodBloomFilter {
    pub fn new(config: L7Config) -> Self {
        info!("Initializing HTTP Method Bloom Filter");

        // Small filter for HTTP methods (short strings)
        let filter_size = scaled_bloom_size(100_000, config.bloom_filter_scale, 32_768);
        let hash_functions = 3;

        Self {
            bloom_filter: BloomFilter::new(filter_size, hash_functions),
            insert_count: AtomicU64::new(0),
            hit_count: AtomicU64::new(0),
        }
    }

    pub fn contains(&self, method: &str) -> bool {
        let bytes = method.as_bytes();
        let result = self.bloom_filter.contains(bytes);

        if result {
            self.hit_count.fetch_add(1, Ordering::Relaxed);
        }

        debug!(
            "HTTP Method Bloom filter check for '{}': {}",
            method, result
        );
        result
    }

    pub fn insert(&mut self, method: String) {
        let bytes = method.as_bytes();
        self.bloom_filter.insert(bytes);
        self.insert_count.fetch_add(1, Ordering::Relaxed);
        debug!("HTTP Method Bloom filter insert for '{}'", method);
    }

    #[allow(dead_code)]
    pub fn get_stats(&self) -> HttpMethodBloomStats {
        let insert_count = self.insert_count.load(Ordering::Relaxed);
        let hit_count = self.hit_count.load(Ordering::Relaxed);
        let hit_rate = if insert_count > 0 {
            hit_count as f64 / insert_count as f64
        } else {
            0.0
        };

        HttpMethodBloomStats {
            filter_size: self.bloom_filter.size(),
            hash_functions: self.bloom_filter.hash_count(),
            insert_count,
            hit_count,
            hit_rate,
        }
    }
}
