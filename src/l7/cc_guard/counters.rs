use dashmap::DashMap;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::types::{
    DistinctSlidingWindowCounter, PageLoadWindowState, SlidingWindowCounter,
    WeightedSlidingWindowCounter,
};
use super::unix_timestamp;

impl SlidingWindowCounter {
    pub(super) fn new() -> Self {
        Self {
            events: Mutex::new(VecDeque::new()),
            last_seen_unix: AtomicI64::new(unix_timestamp()),
        }
    }

    pub(super) fn observe(&mut self, now: Instant, unix_now: i64, window: Duration) -> u32 {
        let mut events = self.events.lock().expect("cc bucket lock poisoned");
        while let Some(front) = events.front() {
            if now.duration_since(*front) > window {
                events.pop_front();
            } else {
                break;
            }
        }
        events.push_back(now);
        self.last_seen_unix.store(unix_now, Ordering::Relaxed);
        events.len() as u32
    }
}

impl WeightedSlidingWindowCounter {
    pub(super) fn new() -> Self {
        Self {
            events: Mutex::new(VecDeque::new()),
            total_weight: AtomicU64::new(0),
            last_seen_unix: AtomicI64::new(unix_timestamp()),
        }
    }

    pub(super) fn observe(
        &mut self,
        now: Instant,
        unix_now: i64,
        window: Duration,
        weight_percent: u8,
    ) -> u32 {
        let mut events = self
            .events
            .lock()
            .expect("cc weighted bucket lock poisoned");
        let mut total_weight = self.total_weight.load(Ordering::Relaxed) as u32;
        while let Some((front, _)) = events.front() {
            if now.duration_since(*front) > window {
                if let Some((_, expired_weight)) = events.pop_front() {
                    total_weight = total_weight.saturating_sub(u32::from(expired_weight));
                }
            } else {
                break;
            }
        }
        let weight = u16::from(weight_percent.max(1));
        events.push_back((now, weight));
        total_weight = total_weight.saturating_add(u32::from(weight));
        self.total_weight
            .store(u64::from(total_weight), Ordering::Relaxed);
        self.last_seen_unix.store(unix_now, Ordering::Relaxed);
        total_weight
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
            events: Mutex::new(VecDeque::new()),
            counts: Mutex::new(HashMap::new()),
            last_seen_unix: AtomicI64::new(unix_timestamp()),
        }
    }

    pub(super) fn observe(
        &mut self,
        value: String,
        now: Instant,
        unix_now: i64,
        window: Duration,
    ) -> u32 {
        let mut events = self
            .events
            .lock()
            .expect("cc distinct bucket lock poisoned");
        let mut counts = self
            .counts
            .lock()
            .expect("cc distinct counts lock poisoned");
        while let Some((front, _)) = events.front() {
            if now.duration_since(*front) > window {
                if let Some((_, expired)) = events.pop_front() {
                    if let Some(count) = counts.get_mut(&expired) {
                        *count = count.saturating_sub(1);
                        if *count == 0 {
                            counts.remove(&expired);
                        }
                    }
                }
            } else {
                break;
            }
        }
        events.push_back((now, value.clone()));
        *counts.entry(value).or_insert(0) += 1;
        self.last_seen_unix.store(unix_now, Ordering::Relaxed);
        counts.len().min(u32::MAX as usize) as u32
    }
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
