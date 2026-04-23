use dashmap::DashMap;
use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use super::types::{
    DistinctSlidingWindowCounter, DistinctWindowSlot, DistinctWindowState, FastWindowCounter,
    FastWindowObservation, FastWindowSlot, FastWindowState, FixedWindowSlot, FixedWindowState,
    HotBlockEntry, PageLoadWindowState, SlidingWindowCounter, WeightedSlidingWindowCounter,
    FAST_WINDOW_BUCKETS, MAX_TRACKED_DISTINCT_VALUES,
};
use super::unix_timestamp;
use crate::locks::mutex_lock;

impl SlidingWindowCounter {
    pub(super) fn new() -> Self {
        Self {
            state: Mutex::new(FixedWindowState::new()),
            last_seen_unix: AtomicI64::new(unix_timestamp()),
        }
    }

    pub(super) fn observe(&mut self, unix_now: i64, window: Duration) -> u32 {
        let mut state = mutex_lock(&self.state, "cc bucket");
        state.observe(unix_now, window, 1);
        self.last_seen_unix.store(unix_now, Ordering::Relaxed);
        state.sum(unix_now, window)
    }
}

impl WeightedSlidingWindowCounter {
    pub(super) fn new() -> Self {
        Self {
            state: Mutex::new(FixedWindowState::new()),
            last_seen_unix: AtomicI64::new(unix_timestamp()),
        }
    }

    pub(super) fn observe(&mut self, unix_now: i64, window: Duration, weight_percent: u8) -> u32 {
        let mut state = mutex_lock(&self.state, "cc weighted bucket");
        let weight = u16::from(weight_percent.max(1));
        state.observe(unix_now, window, u32::from(weight));
        self.last_seen_unix.store(unix_now, Ordering::Relaxed);
        state.sum(unix_now, window)
    }
}

impl PageLoadWindowState {
    pub(super) fn new(expires_at_unix: i64, unix_now: i64) -> Self {
        Self {
            expires_at_unix: AtomicI64::new(expires_at_unix),
            last_seen_unix: AtomicI64::new(unix_now),
        }
    }

    pub(super) fn refresh(&mut self, expires_at_unix: i64, unix_now: i64) {
        self.expires_at_unix
            .store(expires_at_unix, Ordering::Relaxed);
        self.last_seen_unix.store(unix_now, Ordering::Relaxed);
    }

    pub(super) fn is_active(&self, unix_now: i64) -> bool {
        self.expires_at_unix.load(Ordering::Relaxed) >= unix_now
    }
}

impl DistinctSlidingWindowCounter {
    pub(super) fn new() -> Self {
        Self {
            state: Mutex::new(DistinctWindowState::new()),
            last_seen_unix: AtomicI64::new(unix_timestamp()),
        }
    }

    pub(super) fn observe(&mut self, value: String, unix_now: i64, window: Duration) -> u32 {
        let mut state = mutex_lock(&self.state, "cc distinct bucket");
        state.observe(hash_distinct_value(&value), unix_now, window);
        self.last_seen_unix.store(unix_now, Ordering::Relaxed);
        state.len()
    }
}

impl FixedWindowState {
    fn new() -> Self {
        Self {
            slots: [FixedWindowSlot::default(); super::types::FIXED_WINDOW_SLOTS],
        }
    }

    fn observe(&mut self, unix_now: i64, window: Duration, increment: u32) {
        let index = unix_now.rem_euclid(super::types::FIXED_WINDOW_SLOTS as i64) as usize;
        let slot = &mut self.slots[index];
        if slot.tick != unix_now {
            slot.tick = unix_now;
            slot.count = 0;
        }
        slot.count = slot.count.saturating_add(increment.max(1));
        self.clear_stale(unix_now, window);
    }

    fn sum(&self, unix_now: i64, window: Duration) -> u32 {
        let oldest_tick = window_start(unix_now, window);
        self.slots
            .iter()
            .filter(|slot| slot.tick >= oldest_tick && slot.tick <= unix_now)
            .fold(0u32, |acc, slot| acc.saturating_add(slot.count))
    }

    fn clear_stale(&mut self, unix_now: i64, window: Duration) {
        let oldest_tick = window_start(unix_now, window);
        for slot in &mut self.slots {
            if slot.tick < oldest_tick || slot.tick > unix_now {
                slot.tick = 0;
                slot.count = 0;
            }
        }
    }
}

impl DistinctWindowState {
    fn new() -> Self {
        Self {
            slots: [DistinctWindowSlot::default(); super::types::DISTINCT_WINDOW_SLOTS],
            counts: HashMap::new(),
            saturated: false,
            next_index: 0,
        }
    }

    fn observe(&mut self, hash: u64, unix_now: i64, window: Duration) {
        self.evict_stale(unix_now, window);
        if !self.counts.contains_key(&hash) && self.counts.len() >= MAX_TRACKED_DISTINCT_VALUES {
            self.saturated = true;
            return;
        }

        let index = self.next_index % super::types::DISTINCT_WINDOW_SLOTS;
        self.next_index = self.next_index.wrapping_add(1);
        if self.slots[index].occupied {
            let previous_hash = self.slots[index].hash;
            self.remove_hash(previous_hash);
        }

        let slot = &mut self.slots[index];
        slot.tick = unix_now;
        slot.hash = hash;
        slot.occupied = true;
        *self.counts.entry(hash).or_insert(0) += 1;
    }

    fn len(&self) -> u32 {
        let base = self.counts.len().min(u32::MAX as usize) as u32;
        if self.saturated {
            base.saturating_add(1)
        } else {
            base
        }
    }

    fn evict_stale(&mut self, unix_now: i64, window: Duration) {
        let oldest_tick = window_start(unix_now, window);
        let mut expired_hashes = Vec::new();
        for slot in &mut self.slots {
            if slot.occupied && (slot.tick < oldest_tick || slot.tick > unix_now) {
                expired_hashes.push(slot.hash);
                slot.tick = 0;
                slot.hash = 0;
                slot.occupied = false;
            }
        }
        for hash in expired_hashes {
            self.remove_hash(hash);
        }
        if self.counts.len() < MAX_TRACKED_DISTINCT_VALUES {
            self.saturated = false;
        }
    }

    fn remove_hash(&mut self, hash: u64) {
        if let Some(count) = self.counts.get_mut(&hash) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.counts.remove(&hash);
            }
        }
    }
}

impl FastWindowState {
    fn new(unix_now: i64) -> Self {
        Self {
            slots: [FastWindowSlot {
                tick: unix_now,
                count: 0,
            }; FAST_WINDOW_BUCKETS],
        }
    }
}

impl FastWindowCounter {
    pub(super) fn new(unix_now: i64) -> Self {
        Self {
            state: Mutex::new(FastWindowState::new(unix_now)),
            last_seen_unix: AtomicI64::new(unix_now),
        }
    }

    pub(super) fn observe(
        &self,
        unix_now: i64,
        window_secs: u64,
        increment: u32,
    ) -> FastWindowObservation {
        let mut state = mutex_lock(&self.state, "cc fast bucket");
        let index = unix_now.rem_euclid(FAST_WINDOW_BUCKETS as i64) as usize;
        let slot = &mut state.slots[index];
        if slot.tick != unix_now {
            slot.tick = unix_now;
            slot.count = 0;
        }
        slot.count = slot.count.saturating_add(increment.max(1));

        let oldest_tick = unix_now.saturating_sub(window_secs.max(1) as i64 - 1);
        let count = state
            .slots
            .iter()
            .filter(|slot| slot.tick >= oldest_tick && slot.tick <= unix_now)
            .fold(0u32, |acc, slot| acc.saturating_add(slot.count));
        self.last_seen_unix.store(unix_now, Ordering::Relaxed);
        FastWindowObservation { count }
    }
}

impl HotBlockEntry {
    pub(super) fn new(expires_at_unix: i64, unix_now: i64) -> Self {
        Self {
            expires_at_unix: AtomicI64::new(expires_at_unix),
            last_seen_unix: AtomicI64::new(unix_now),
            hits: AtomicU64::new(0),
        }
    }

    pub(super) fn is_active(&self, unix_now: i64) -> bool {
        self.last_seen_unix.store(unix_now, Ordering::Relaxed);
        self.expires_at_unix.load(Ordering::Relaxed) >= unix_now
    }

    pub(super) fn record_hit_and_extend(&self, unix_now: i64, base_ttl_secs: u64) -> bool {
        if !self.is_active(unix_now) {
            return false;
        }
        let hits = self.hits.fetch_add(1, Ordering::Relaxed).saturating_add(1);
        if hits % 64 != 0 {
            return true;
        }
        let ttl = adaptive_hot_cache_ttl(base_ttl_secs, hits);
        let expires_at = unix_now.saturating_add(ttl as i64);
        let current = self.expires_at_unix.load(Ordering::Relaxed);
        if expires_at > current {
            self.expires_at_unix.store(expires_at, Ordering::Relaxed);
        }
        true
    }

    pub(super) fn refresh(&self, expires_at_unix: i64, unix_now: i64) {
        self.expires_at_unix
            .store(expires_at_unix, Ordering::Relaxed);
        self.last_seen_unix.store(unix_now, Ordering::Relaxed);
        self.hits.fetch_add(1, Ordering::Relaxed);
    }
}

pub(super) fn adaptive_hot_cache_ttl(base_ttl_secs: u64, hits: u64) -> u64 {
    let base = base_ttl_secs.max(3);
    let multiplier = match hits {
        0..=1 => 1,
        2..=4 => 2,
        5..=15 => 4,
        16..=63 => 8,
        _ => 12,
    };
    base.saturating_mul(multiplier).clamp(3, 900)
}

fn window_start(unix_now: i64, window: Duration) -> i64 {
    unix_now.saturating_sub(window.as_secs().max(1) as i64 - 1)
}

fn hash_distinct_value(value: &str) -> u64 {
    use std::hash::{Hash, Hasher};

    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

pub(super) fn weighted_points_to_requests(points: u32) -> u32 {
    if points == 0 {
        return 0;
    }
    points.div_ceil(100)
}

pub(super) fn cleanup_interval_for_size(size: usize) -> u64 {
    match size {
        0..=2_047 => 1_024,
        2_048..=8_191 => 256,
        _ => 64,
    }
}

pub(super) fn cleanup_batch_for_size(size: usize) -> usize {
    match size {
        0..=2_047 => 128,
        2_048..=8_191 => 512,
        _ => 2_048,
    }
}

pub(super) fn cleanup_map(
    map: &DashMap<String, SlidingWindowCounter>,
    stale_before: i64,
    limit: usize,
) {
    let keys = map
        .iter()
        .filter(|entry| entry.value().last_seen_unix.load(Ordering::Relaxed) < stale_before)
        .take(limit)
        .map(|entry| entry.key().clone())
        .collect::<Vec<_>>();

    for key in keys {
        map.remove(&key);
    }
}

pub(super) fn cleanup_weighted_map(
    map: &DashMap<String, WeightedSlidingWindowCounter>,
    stale_before: i64,
    limit: usize,
) {
    let keys = map
        .iter()
        .filter(|entry| entry.value().last_seen_unix.load(Ordering::Relaxed) < stale_before)
        .take(limit)
        .map(|entry| entry.key().clone())
        .collect::<Vec<_>>();

    for key in keys {
        map.remove(&key);
    }
}

pub(super) fn cleanup_distinct_map(
    map: &DashMap<String, DistinctSlidingWindowCounter>,
    stale_before: i64,
    limit: usize,
) {
    let keys = map
        .iter()
        .filter(|entry| entry.value().last_seen_unix.load(Ordering::Relaxed) < stale_before)
        .take(limit)
        .map(|entry| entry.key().clone())
        .collect::<Vec<_>>();

    for key in keys {
        map.remove(&key);
    }
}

pub(super) fn cleanup_page_window_map(
    map: &DashMap<String, PageLoadWindowState>,
    unix_now: i64,
    stale_before: i64,
    limit: usize,
) {
    let keys = map
        .iter()
        .filter(|entry| {
            let value = entry.value();
            value.expires_at_unix.load(Ordering::Relaxed) < unix_now
                && value.last_seen_unix.load(Ordering::Relaxed) < stale_before
        })
        .take(limit)
        .map(|entry| entry.key().clone())
        .collect::<Vec<_>>();

    for key in keys {
        map.remove(&key);
    }
}

pub(super) fn cleanup_fast_window_map(
    map: &DashMap<String, FastWindowCounter>,
    stale_before: i64,
    limit: usize,
) {
    let keys = map
        .iter()
        .filter(|entry| entry.value().last_seen_unix.load(Ordering::Relaxed) < stale_before)
        .take(limit)
        .map(|entry| entry.key().clone())
        .collect::<Vec<_>>();

    for key in keys {
        map.remove(&key);
    }
}

pub(super) fn cleanup_hot_block_map(
    map: &DashMap<String, HotBlockEntry>,
    unix_now: i64,
    stale_before: i64,
    limit: usize,
) {
    let keys = map
        .iter()
        .filter(|entry| {
            entry.value().expires_at_unix.load(Ordering::Relaxed) < unix_now
                && entry.value().last_seen_unix.load(Ordering::Relaxed) < stale_before
        })
        .take(limit)
        .map(|entry| entry.key().clone())
        .collect::<Vec<_>>();

    for key in keys {
        map.remove(&key);
    }
}
