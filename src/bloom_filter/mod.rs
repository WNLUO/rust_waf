// Public Bloom Filter implementation
pub struct BloomFilter {
    data: Vec<u8>,
    size: usize,
    hash_count: usize,
}

impl BloomFilter {
    pub fn new(size: usize, hash_count: usize) -> Self {
        let byte_count = (size + 7) / 8;
        Self {
            data: vec![0u8; byte_count],
            size,
            hash_count,
        }
    }

    pub fn contains(&self, item: &[u8]) -> bool {
        for i in 0..self.hash_count {
            let hash = self.hash_item(item, i);
            let byte_index = (hash % self.size) / 8;
            let bit_mask = 1u8 << (hash % 8);

            if self
                .data
                .get(byte_index)
                .map_or(true, |&byte| byte & bit_mask == 0)
            {
                return false;
            }
        }
        true
    }

    pub fn insert(&mut self, item: &[u8]) {
        for i in 0..self.hash_count {
            let hash = self.hash_item(item, i);
            let byte_index = (hash % self.size) / 8;
            let bit_mask = 1u8 << (hash % 8);

            if let Some(byte) = self.data.get_mut(byte_index) {
                *byte |= bit_mask;
            }
        }
    }

    fn hash_item(&self, item: &[u8], seed: usize) -> usize {
        let mut hash: usize = seed;
        for &byte in item.iter() {
            hash = hash.wrapping_mul(31).wrapping_add(byte as usize);
        }
        hash
    }

    pub fn size(&self) -> usize {
        self.size
    }

    pub fn hash_count(&self) -> usize {
        self.hash_count
    }
}

pub fn scaled_bloom_size(base_bits: usize, scale: f64, min_bits: usize) -> usize {
    let scale = scale.clamp(0.1, 1.0);
    let scaled = (base_bits as f64 * scale).round() as usize;
    scaled.max(min_bits)
}
