use std::collections::VecDeque;
use std::sync::atomic::AtomicI64;
use std::sync::Mutex;
use std::time::Instant;

#[derive(Debug, Clone)]
pub struct BehaviorProfileSnapshot {
    pub identity: String,
    pub source_ip: Option<String>,
    pub latest_seen_unix: i64,
    pub score: u32,
    pub dominant_route: Option<String>,
    pub focused_document_route: Option<String>,
    pub focused_api_route: Option<String>,
    pub distinct_routes: usize,
    pub distinct_client_ips: usize,
    pub distinct_user_agents: usize,
    pub distinct_header_signatures: usize,
    pub repeated_ratio_percent: u32,
    pub client_ip_repeated_ratio_percent: u32,
    pub document_repeated_ratio_percent: u32,
    pub api_repeated_ratio_percent: u32,
    pub jitter_ms: Option<u64>,
    pub document_requests: usize,
    pub api_requests: usize,
    pub non_document_requests: usize,
    pub recent_challenges: usize,
    pub session_span_secs: u64,
    pub flags: Vec<String>,
    pub latest_route: String,
    pub latest_kind: &'static str,
}

#[derive(Debug)]
pub(super) struct BehaviorWindow {
    pub(super) samples: Mutex<VecDeque<RequestSample>>,
    pub(super) challenge_hits: Mutex<VecDeque<Instant>>,
    pub(super) last_seen_unix: AtomicI64,
}

#[derive(Debug, Clone)]
pub(super) struct RequestSample {
    pub(super) route: String,
    pub(super) kind: RequestKind,
    pub(super) client_ip: Option<String>,
    pub(super) user_agent: Option<String>,
    pub(super) header_signature: Option<String>,
    pub(super) at: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RequestKind {
    Document,
    Static,
    Api,
    Other,
}

#[derive(Debug, Clone)]
pub(super) struct BehaviorAssessment {
    pub(super) identity: String,
    pub(super) score: u32,
    pub(super) dominant_route: Option<String>,
    pub(super) distinct_routes: usize,
    pub(super) distinct_client_ips: usize,
    pub(super) distinct_user_agents: usize,
    pub(super) distinct_header_signatures: usize,
    pub(super) repeated_ratio_percent: u32,
    pub(super) client_ip_repeated_ratio_percent: u32,
    pub(super) document_repeated_ratio_percent: u32,
    pub(super) focused_document_route: Option<String>,
    pub(super) focused_api_route: Option<String>,
    pub(super) api_repeated_ratio_percent: u32,
    pub(super) jitter_ms: Option<u64>,
    pub(super) document_requests: usize,
    pub(super) api_requests: usize,
    pub(super) non_document_requests: usize,
    pub(super) recent_challenges: usize,
    pub(super) session_span_secs: u64,
    pub(super) flags: Vec<&'static str>,
}
