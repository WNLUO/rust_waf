use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicI64, AtomicU64};
use std::sync::Mutex;
use std::time::Instant;

pub(super) const BYPASS_PATHS: &[&str] = &["/.well-known/waf/browser-fingerprint-report"];
pub(super) const API_REQUEST_WEIGHT_PERCENT: u8 = 140;
pub(super) const MAX_COUNTER_BUCKETS: usize = 65_536;
pub(super) const MAX_PAGE_WINDOW_BUCKETS: usize = 32_768;
pub(super) const MAX_BUCKET_KEY_LEN: usize = 192;
pub(super) const MAX_ROUTE_PATH_LEN: usize = 160;
pub(super) const MAX_HOST_LEN: usize = 96;
pub(super) const OVERFLOW_SHARDS: u64 = 64;

#[derive(Debug)]
pub(super) struct SlidingWindowCounter {
    pub(super) events: Mutex<VecDeque<Instant>>,
    pub(super) last_seen_unix: AtomicI64,
}

#[derive(Debug)]
pub(super) struct WeightedSlidingWindowCounter {
    pub(super) events: Mutex<VecDeque<(Instant, u16)>>,
    pub(super) total_weight: AtomicU64,
    pub(super) last_seen_unix: AtomicI64,
}

#[derive(Debug)]
pub(super) struct PageLoadWindowState {
    pub(super) expires_at_unix: AtomicI64,
    pub(super) last_seen_unix: AtomicI64,
}

#[derive(Debug)]
pub(super) struct DistinctSlidingWindowCounter {
    pub(super) events: Mutex<VecDeque<(Instant, String)>>,
    pub(super) counts: Mutex<HashMap<String, u32>>,
    pub(super) last_seen_unix: AtomicI64,
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
