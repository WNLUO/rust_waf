use crate::core::InspectionLayer;
use std::sync::atomic::{AtomicU64, Ordering};

pub struct MetricsCollector {
    total_packets: AtomicU64,
    blocked_packets: AtomicU64,
    blocked_l4: AtomicU64,
    blocked_l7: AtomicU64,
    total_bytes: AtomicU64,
}

impl MetricsCollector {
    pub fn new() -> Self {
        Self {
            total_packets: AtomicU64::new(0),
            blocked_packets: AtomicU64::new(0),
            blocked_l4: AtomicU64::new(0),
            blocked_l7: AtomicU64::new(0),
            total_bytes: AtomicU64::new(0),
        }
    }

    pub fn record_packet(&self, bytes: usize) {
        self.total_packets.fetch_add(1, Ordering::Relaxed);
        self.total_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub fn record_block(&self, layer: InspectionLayer) {
        self.blocked_packets.fetch_add(1, Ordering::Relaxed);
        match layer {
            InspectionLayer::L4 => {
                self.blocked_l4.fetch_add(1, Ordering::Relaxed);
            }
            InspectionLayer::L7 => {
                self.blocked_l7.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub fn get_stats(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            total_packets: self.total_packets.load(Ordering::Relaxed),
            blocked_packets: self.blocked_packets.load(Ordering::Relaxed),
            blocked_l4: self.blocked_l4.load(Ordering::Relaxed),
            blocked_l7: self.blocked_l7.load(Ordering::Relaxed),
            total_bytes: self.total_bytes.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone)]
pub struct MetricsSnapshot {
    pub total_packets: u64,
    pub blocked_packets: u64,
    pub blocked_l4: u64,
    pub blocked_l7: u64,
    pub total_bytes: u64,
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}
