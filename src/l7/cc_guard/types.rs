use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, AtomicU64};
use std::sync::Mutex;

pub(super) const BYPASS_PATHS: &[&str] = &["/.well-known/waf/browser-fingerprint-report"];
pub(super) const API_REQUEST_WEIGHT_PERCENT: u8 = 140;
pub(super) const MAX_COUNTER_BUCKETS: usize = 65_536;
pub(super) const MAX_PAGE_WINDOW_BUCKETS: usize = 32_768;
pub(super) const MAX_BUCKET_KEY_LEN: usize = 192;
pub(super) const MAX_ROUTE_PATH_LEN: usize = 160;
pub(super) const MAX_HOST_LEN: usize = 96;
pub(super) const OVERFLOW_SHARDS: u64 = 64;
pub(super) const FAST_WINDOW_BUCKETS: usize = 8;
pub(super) const FIXED_WINDOW_SLOTS: usize = 128;
pub(super) const DISTINCT_WINDOW_SLOTS: usize = 512;
pub(super) const MAX_TRACKED_DISTINCT_VALUES: usize = 256;

#[derive(Debug)]
pub(super) struct SlidingWindowCounter {
    pub(super) state: Mutex<FixedWindowState>,
    pub(super) last_seen_unix: AtomicI64,
}

#[derive(Debug)]
pub(super) struct WeightedSlidingWindowCounter {
    pub(super) state: Mutex<FixedWindowState>,
    pub(super) last_seen_unix: AtomicI64,
}

#[derive(Debug)]
pub(super) struct PageLoadWindowState {
    pub(super) expires_at_unix: AtomicI64,
    pub(super) last_seen_unix: AtomicI64,
}

#[derive(Debug)]
pub(super) struct DistinctSlidingWindowCounter {
    pub(super) state: Mutex<DistinctWindowState>,
    pub(super) last_seen_unix: AtomicI64,
}

#[derive(Debug)]
pub(super) struct FastWindowCounter {
    pub(super) state: Mutex<FastWindowState>,
    pub(super) last_seen_unix: AtomicI64,
}

#[derive(Debug, Clone)]
pub(super) struct FastWindowState {
    pub(super) slots: [FastWindowSlot; FAST_WINDOW_BUCKETS],
}

#[derive(Debug, Clone, Copy, Default)]
pub(super) struct FastWindowSlot {
    pub(super) tick: i64,
    pub(super) count: u32,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct FastWindowObservation {
    pub(super) count: u32,
}

#[derive(Debug, Clone)]
pub(super) struct FixedWindowState {
    pub(super) slots: [FixedWindowSlot; FIXED_WINDOW_SLOTS],
}

#[derive(Debug, Clone, Copy, Default)]
pub(super) struct FixedWindowSlot {
    pub(super) tick: i64,
    pub(super) count: u32,
}

#[derive(Debug)]
pub(super) struct DistinctWindowState {
    pub(super) slots: [DistinctWindowSlot; DISTINCT_WINDOW_SLOTS],
    pub(super) counts: HashMap<u64, u16>,
    pub(super) saturated: bool,
    pub(super) next_index: usize,
}

#[derive(Debug, Clone, Copy, Default)]
pub(super) struct DistinctWindowSlot {
    pub(super) tick: i64,
    pub(super) hash: u64,
    pub(super) occupied: bool,
}

#[derive(Debug)]
pub(super) struct HotBlockEntry {
    pub(super) expires_at_unix: AtomicI64,
    pub(super) last_seen_unix: AtomicI64,
    pub(super) hits: AtomicU64,
}

#[derive(Debug)]
pub(super) enum SurvivalFastPathResult {
    Block(crate::core::InspectionResult),
    Challenge(crate::core::InspectionResult),
    NoDecision,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum HtmlResponseMode {
    HtmlChallenge,
    TextOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RequestKind {
    Document,
    StaticAsset,
    ApiLike,
    Other,
}

impl RequestKind {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Document => "document",
            Self::StaticAsset => "static",
            Self::ApiLike => "api",
            Self::Other => "other",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CcTrackingMode {
    Rich,
    Core,
    Minimal,
}

impl CcTrackingMode {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Rich => "rich",
            Self::Core => "core",
            Self::Minimal => "minimal",
        }
    }

    pub(super) fn uses_page_windows(self) -> bool {
        matches!(self, Self::Rich)
    }

    pub(super) fn uses_weighted_buckets(self) -> bool {
        matches!(self, Self::Rich)
    }

    pub(super) fn uses_distinct_hot_path_clients(self, kind: RequestKind) -> bool {
        matches!(self, Self::Rich) || (matches!(self, Self::Core) && kind == RequestKind::ApiLike)
    }
}
