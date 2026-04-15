use crate::core::{CustomHttpResponse, InspectionLayer, InspectionResult};
use crate::protocol::UnifiedHttpRequest;
use dashmap::DashMap;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const BEHAVIOR_WINDOW_SECS: u64 = 300;
const ACTIVE_PROFILE_IDLE_SECS: i64 = 60;
const MAX_SAMPLES_PER_IDENTITY: usize = 96;
const CLEANUP_EVERY_REQUESTS: u64 = 512;
const CHALLENGE_SCORE: u32 = 60;
const BLOCK_SCORE: u32 = 90;
const DELAY_SCORE: u32 = 35;
const DELAY_MS: u64 = 250;
pub const AUTO_BLOCK_DURATION_SECS: u64 = 15 * 60;
const CHALLENGES_BEFORE_AUTO_BLOCK: usize = 2;

#[derive(Debug)]
pub struct L7BehaviorGuard {
    buckets: DashMap<String, BehaviorWindow>,
    request_sequence: AtomicU64,
}

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
    pub repeated_ratio_percent: u32,
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
struct BehaviorWindow {
    samples: Mutex<VecDeque<RequestSample>>,
    challenge_hits: Mutex<VecDeque<Instant>>,
    last_seen_unix: AtomicI64,
}

#[derive(Debug, Clone)]
struct RequestSample {
    route: String,
    kind: RequestKind,
    client_ip: Option<String>,
    at: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequestKind {
    Document,
    Static,
    Api,
    Other,
}

#[derive(Debug, Clone)]
struct BehaviorAssessment {
    identity: String,
    score: u32,
    dominant_route: Option<String>,
    distinct_routes: usize,
    repeated_ratio_percent: u32,
    document_repeated_ratio_percent: u32,
    focused_document_route: Option<String>,
    focused_api_route: Option<String>,
    api_repeated_ratio_percent: u32,
    jitter_ms: Option<u64>,
    document_requests: usize,
    api_requests: usize,
    non_document_requests: usize,
    recent_challenges: usize,
    session_span_secs: u64,
    flags: Vec<&'static str>,
}

impl L7BehaviorGuard {
    pub fn new() -> Self {
        Self {
            buckets: DashMap::new(),
            request_sequence: AtomicU64::new(0),
        }
    }

    pub async fn inspect_request(
        &self,
        request: &mut UnifiedHttpRequest,
    ) -> Option<InspectionResult> {
        let Some(identity) = request_identity(request) else {
            return None;
        };
        let route = request
            .get_metadata("l7.cc.route")
            .cloned()
            .unwrap_or_else(|| normalized_route_path(request_path(&request.uri)));
        let kind = request_kind(request);
        let client_ip = request
            .client_ip
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string);
        let now = Instant::now();
        let unix_now = unix_timestamp();
        let window = Duration::from_secs(BEHAVIOR_WINDOW_SECS);
        let assessment =
            self.observe_and_assess(&identity, route, kind, client_ip, now, unix_now, window);

        request.add_metadata(
            "l7.behavior.identity".to_string(),
            assessment.identity.clone(),
        );
        request.add_metadata(
            "l7.behavior.score".to_string(),
            assessment.score.to_string(),
        );
        request.add_metadata(
            "l7.behavior.distinct_routes".to_string(),
            assessment.distinct_routes.to_string(),
        );
        request.add_metadata(
            "l7.behavior.repeated_ratio".to_string(),
            assessment.repeated_ratio_percent.to_string(),
        );
        request.add_metadata(
            "l7.behavior.document_repeated_ratio".to_string(),
            assessment.document_repeated_ratio_percent.to_string(),
        );
        request.add_metadata(
            "l7.behavior.document_requests".to_string(),
            assessment.document_requests.to_string(),
        );
        request.add_metadata(
            "l7.behavior.api_requests".to_string(),
            assessment.api_requests.to_string(),
        );
        request.add_metadata(
            "l7.behavior.non_document_requests".to_string(),
            assessment.non_document_requests.to_string(),
        );
        request.add_metadata(
            "l7.behavior.api_repeated_ratio".to_string(),
            assessment.api_repeated_ratio_percent.to_string(),
        );
        request.add_metadata(
            "l7.behavior.challenge_count_window".to_string(),
            assessment.recent_challenges.to_string(),
        );
        request.add_metadata(
            "l7.behavior.session_span_secs".to_string(),
            assessment.session_span_secs.to_string(),
        );
        if !assessment.flags.is_empty() {
            request.add_metadata("l7.behavior.flags".to_string(), assessment.flags.join(","));
        }
        if let Some(route) = assessment.dominant_route.as_ref() {
            request.add_metadata("l7.behavior.dominant_route".to_string(), route.clone());
        }
        if let Some(route) = assessment.focused_document_route.as_ref() {
            request.add_metadata(
                "l7.behavior.focused_document_route".to_string(),
                route.clone(),
            );
        }
        if let Some(route) = assessment.focused_api_route.as_ref() {
            request.add_metadata("l7.behavior.focused_api_route".to_string(), route.clone());
        }
        if let Some(jitter_ms) = assessment.jitter_ms {
            request.add_metadata(
                "l7.behavior.interval_jitter_ms".to_string(),
                jitter_ms.to_string(),
            );
        }

        self.maybe_cleanup(unix_now);

        let should_auto_block = assessment.score >= BLOCK_SCORE
            || (assessment.score >= CHALLENGE_SCORE
                && assessment.recent_challenges >= CHALLENGES_BEFORE_AUTO_BLOCK);

        if should_auto_block {
            self.record_block(&assessment.identity, now, window);
            request.add_metadata("l7.behavior.action".to_string(), "block".to_string());
            let reason = format!(
                "l7 behavior guard blocked suspicious session: score={} repeated_ratio={} document_repeated_ratio={} distinct_routes={} dominant_route={} recent_challenges={} flags={}",
                assessment.score,
                assessment.repeated_ratio_percent,
                assessment.document_repeated_ratio_percent,
                assessment.distinct_routes,
                assessment.dominant_route.as_deref().unwrap_or("*"),
                assessment.recent_challenges,
                assessment.flags.join("|"),
            );
            return Some(InspectionResult::respond_and_persist_ip(
                InspectionLayer::L7,
                reason.clone(),
                build_behavior_response(request, 429, "行为异常，请稍后重试", &reason),
            ));
        }

        if assessment.score >= CHALLENGE_SCORE {
            self.record_challenge(&assessment.identity, now, window);
            request.add_metadata("l7.behavior.action".to_string(), "challenge".to_string());
            let reason = format!(
                "l7 behavior guard challenged suspicious session: score={} repeated_ratio={} document_repeated_ratio={} distinct_routes={} dominant_route={} recent_challenges={} flags={}",
                assessment.score,
                assessment.repeated_ratio_percent,
                assessment.document_repeated_ratio_percent,
                assessment.distinct_routes,
                assessment.dominant_route.as_deref().unwrap_or("*"),
                assessment.recent_challenges,
                assessment.flags.join("|"),
            );
            return Some(InspectionResult::respond(
                InspectionLayer::L7,
                reason.clone(),
                build_behavior_response(request, 429, "访问行为异常，请稍后再试", &reason),
            ));
        }

        if assessment.score >= DELAY_SCORE {
            request.add_metadata(
                "l7.behavior.action".to_string(),
                format!("delay:{DELAY_MS}ms"),
            );
            tokio::time::sleep(Duration::from_millis(DELAY_MS)).await;
        }

        None
    }

    fn observe_and_assess(
        &self,
        identity: &str,
        route: String,
        kind: RequestKind,
        client_ip: Option<String>,
        now: Instant,
        unix_now: i64,
        window: Duration,
    ) -> BehaviorAssessment {
        let mut entry = self
            .buckets
            .entry(identity.to_string())
            .or_insert_with(BehaviorWindow::new);
        entry.observe_and_assess(
            identity.to_string(),
            route,
            kind,
            client_ip,
            now,
            unix_now,
            window,
        )
    }

    fn maybe_cleanup(&self, unix_now: i64) {
        let sequence = self.request_sequence.fetch_add(1, Ordering::Relaxed) + 1;
        if !sequence.is_multiple_of(CLEANUP_EVERY_REQUESTS) {
            return;
        }

        let stale_before = unix_now - (BEHAVIOR_WINDOW_SECS as i64 * 3).max(180);
        let keys = self
            .buckets
            .iter()
            .filter(|entry| entry.value().last_seen_unix.load(Ordering::Relaxed) < stale_before)
            .take(512)
            .map(|entry| entry.key().clone())
            .collect::<Vec<_>>();
        for key in keys {
            self.buckets.remove(&key);
        }
    }

    fn record_challenge(&self, identity: &str, now: Instant, window: Duration) {
        if let Some(mut entry) = self.buckets.get_mut(identity) {
            entry.record_challenge(now, window);
        }
    }

    fn record_block(&self, identity: &str, now: Instant, window: Duration) {
        if let Some(mut entry) = self.buckets.get_mut(identity) {
            entry.record_block(now, window);
        }
    }

    pub fn snapshot_profiles(&self, limit: usize) -> Vec<BehaviorProfileSnapshot> {
        let now = Instant::now();
        let unix_now = unix_timestamp();
        let window = Duration::from_secs(BEHAVIOR_WINDOW_SECS);
        let mut profiles = self
            .buckets
            .iter()
            .filter_map(|entry| {
                let last_seen_unix = entry.value().last_seen_unix.load(Ordering::Relaxed);
                if unix_now.saturating_sub(last_seen_unix) > ACTIVE_PROFILE_IDLE_SECS {
                    return None;
                }
                entry.value().snapshot(entry.key().clone(), now, window)
            })
            .collect::<Vec<_>>();
        profiles.sort_by(|left, right| {
            right
                .score
                .cmp(&left.score)
                .then_with(|| right.latest_seen_unix.cmp(&left.latest_seen_unix))
        });
        if limit > 0 && profiles.len() > limit {
            profiles.truncate(limit);
        }
        profiles
    }
}

impl BehaviorWindow {
    fn new() -> Self {
        Self {
            samples: Mutex::new(VecDeque::new()),
            challenge_hits: Mutex::new(VecDeque::new()),
            last_seen_unix: AtomicI64::new(unix_timestamp()),
        }
    }

    fn observe_and_assess(
        &mut self,
        identity: String,
        route: String,
        kind: RequestKind,
        client_ip: Option<String>,
        now: Instant,
        unix_now: i64,
        window: Duration,
    ) -> BehaviorAssessment {
        let mut samples = self.samples.lock().expect("behavior window lock poisoned");
        while let Some(front) = samples.front() {
            if now.duration_since(front.at) > window || samples.len() > MAX_SAMPLES_PER_IDENTITY {
                samples.pop_front();
            } else {
                break;
            }
        }
        samples.push_back(RequestSample {
            route: route.clone(),
            kind,
            client_ip,
            at: now,
        });
        while samples.len() > MAX_SAMPLES_PER_IDENTITY {
            samples.pop_front();
        }
        self.last_seen_unix.store(unix_now, Ordering::Relaxed);
        let recent_challenges = self.recent_challenges(now, window);

        assess_samples(identity, &samples, now, recent_challenges)
    }

    fn recent_challenges(&self, now: Instant, window: Duration) -> usize {
        let mut challenge_hits = self
            .challenge_hits
            .lock()
            .expect("behavior challenge lock poisoned");
        while let Some(front) = challenge_hits.front() {
            if now.duration_since(*front) > window {
                challenge_hits.pop_front();
            } else {
                break;
            }
        }
        challenge_hits.len()
    }

    fn record_challenge(&mut self, now: Instant, window: Duration) {
        let mut challenge_hits = self
            .challenge_hits
            .lock()
            .expect("behavior challenge lock poisoned");
        while let Some(front) = challenge_hits.front() {
            if now.duration_since(*front) > window {
                challenge_hits.pop_front();
            } else {
                break;
            }
        }
        challenge_hits.push_back(now);
    }

    fn record_block(&mut self, now: Instant, window: Duration) {
        let mut challenge_hits = self
            .challenge_hits
            .lock()
            .expect("behavior challenge lock poisoned");
        while let Some(front) = challenge_hits.front() {
            if now.duration_since(*front) > window {
                challenge_hits.pop_front();
            } else {
                break;
            }
        }
        challenge_hits.clear();
    }

    fn snapshot(
        &self,
        identity: String,
        now: Instant,
        window: Duration,
    ) -> Option<BehaviorProfileSnapshot> {
        let mut samples = self.samples.lock().expect("behavior window lock poisoned");
        while let Some(front) = samples.front() {
            if now.duration_since(front.at) > window || samples.len() > MAX_SAMPLES_PER_IDENTITY {
                samples.pop_front();
            } else {
                break;
            }
        }
        if samples.is_empty() {
            return None;
        }
        let samples_snapshot = samples.iter().cloned().collect::<VecDeque<_>>();
        drop(samples);

        let assessment = assess_samples(
            identity.clone(),
            &samples_snapshot,
            now,
            self.recent_challenges(now, window),
        );
        let latest = samples_snapshot.back().cloned()?;
        Some(BehaviorProfileSnapshot {
            identity,
            source_ip: latest.client_ip,
            latest_seen_unix: self.last_seen_unix.load(Ordering::Relaxed),
            score: assessment.score,
            dominant_route: assessment.dominant_route,
            focused_document_route: assessment.focused_document_route,
            focused_api_route: assessment.focused_api_route,
            distinct_routes: assessment.distinct_routes,
            repeated_ratio_percent: assessment.repeated_ratio_percent,
            document_repeated_ratio_percent: assessment.document_repeated_ratio_percent,
            api_repeated_ratio_percent: assessment.api_repeated_ratio_percent,
            jitter_ms: assessment.jitter_ms,
            document_requests: assessment.document_requests,
            api_requests: assessment.api_requests,
            non_document_requests: assessment.non_document_requests,
            recent_challenges: assessment.recent_challenges,
            session_span_secs: assessment.session_span_secs,
            flags: assessment.flags.into_iter().map(str::to_string).collect(),
            latest_route: latest.route,
            latest_kind: latest.kind.as_str(),
        })
    }
}

impl RequestKind {
    fn as_str(self) -> &'static str {
        match self {
            RequestKind::Document => "document",
            RequestKind::Static => "static",
            RequestKind::Api => "api",
            RequestKind::Other => "other",
        }
    }
}

fn assess_samples(
    identity: String,
    samples: &VecDeque<RequestSample>,
    now: Instant,
    recent_challenges: usize,
) -> BehaviorAssessment {
    let mut route_counts: HashMap<&str, usize> = HashMap::new();
    let mut document_route_counts: HashMap<&str, usize> = HashMap::new();
    let mut api_route_counts: HashMap<&str, usize> = HashMap::new();
    let mut api_requests = 0usize;
    let mut document_requests = 0usize;
    let mut non_document_requests = 0usize;
    for sample in samples.iter() {
        *route_counts.entry(sample.route.as_str()).or_insert(0) += 1;
        if matches!(sample.kind, RequestKind::Document) {
            document_requests += 1;
            *document_route_counts
                .entry(sample.route.as_str())
                .or_insert(0) += 1;
        } else if matches!(sample.kind, RequestKind::Api) {
            api_requests += 1;
            non_document_requests += 1;
            *api_route_counts.entry(sample.route.as_str()).or_insert(0) += 1;
        } else {
            non_document_requests += 1;
        }
    }
    let total = samples.len().max(1);
    let dominant = route_counts
        .iter()
        .max_by_key(|(_, count)| **count)
        .map(|(route, count)| ((*route).to_string(), *count))
        .unwrap_or_else(|| ("-".to_string(), 1));
    let repeated_ratio_percent = ((dominant.1 * 100) / total) as u32;
    let distinct_routes = route_counts.len();
    let jitter_ms = interval_jitter_ms(samples);
    let document_dominant = document_route_counts
        .iter()
        .max_by_key(|(_, count)| **count)
        .map(|(route, count)| ((*route).to_string(), *count));
    let document_repeated_ratio_percent = if document_requests == 0 {
        0
    } else {
        document_dominant
            .as_ref()
            .map(|(_, count)| ((*count * 100) / document_requests) as u32)
            .unwrap_or(0)
    };
    let api_dominant = api_route_counts
        .iter()
        .max_by_key(|(_, count)| **count)
        .map(|(route, count)| ((*route).to_string(), *count));
    let api_repeated_ratio_percent = if api_requests == 0 {
        0
    } else {
        api_dominant
            .as_ref()
            .map(|(_, count)| ((*count * 100) / api_requests) as u32)
            .unwrap_or(0)
    };
    let session_span_secs = samples
        .front()
        .map(|first| now.duration_since(first.at).as_secs())
        .unwrap_or(0);
    let broad_navigation_context = total >= 24
        && distinct_routes >= 16
        && repeated_ratio_percent <= 15
        && non_document_requests >= document_requests.saturating_mul(6);

    let mut score = 0u32;
    let mut flags = Vec::new();
    if total >= 8 && repeated_ratio_percent >= 85 {
        score += 35;
        flags.push("repeated_route_burst");
    } else if total >= 6 && repeated_ratio_percent >= 70 {
        score += 20;
        flags.push("repeated_route_bias");
    }
    if total >= 10 && distinct_routes <= 2 {
        score += 20;
        flags.push("low_route_diversity");
    } else if total >= 8 && distinct_routes <= 3 {
        score += 10;
        flags.push("narrow_navigation");
    }
    if document_requests >= 4 && non_document_requests == 0 {
        score += 20;
        flags.push("document_without_followups");
    } else if document_requests >= 5 && non_document_requests.saturating_mul(2) < document_requests
    {
        score += 10;
        flags.push("document_heavy");
    }
    if document_requests >= 5 && document_repeated_ratio_percent >= 80 {
        score += 30;
        flags.push("focused_document_reload");
    } else if document_requests >= 4 && document_repeated_ratio_percent >= 65 {
        score += 15;
        flags.push("focused_document_loop");
    }
    if !broad_navigation_context
        && document_requests >= 3
        && document_repeated_ratio_percent >= 100
        && non_document_requests >= 24
        && session_span_secs <= 30
    {
        score += 60;
        flags.push("document_reload_burst");
    } else if !broad_navigation_context
        && document_requests >= 2
        && document_repeated_ratio_percent >= 100
        && non_document_requests >= 12
        && session_span_secs <= 20
    {
        score += 40;
        flags.push("document_reload_pair");
    }
    if api_requests >= 5 && distinct_routes <= 2 {
        score += 15;
        flags.push("api_route_bias");
    }
    if api_requests >= 4
        && api_repeated_ratio_percent >= 85
        && (!broad_navigation_context || distinct_routes <= 8)
    {
        score += 35;
        flags.push("focused_api_burst");
    } else if api_requests >= 3
        && api_repeated_ratio_percent >= 70
        && (!broad_navigation_context || distinct_routes <= 6)
    {
        score += 20;
        flags.push("focused_api_loop");
    }
    if api_requests >= 3
        && api_repeated_ratio_percent >= 100
        && session_span_secs <= 30
        && distinct_routes <= 3
    {
        score += 25;
        flags.push("single_query_endpoint");
    }
    if is_high_value_route(dominant.0.as_str()) && dominant.1 >= 4 {
        score += 15;
        flags.push("high_value_route_bias");
    }
    if let Some((route, count)) = api_dominant.as_ref() {
        if is_high_value_route(route) && *count >= 3 {
            score += 20;
            flags.push("high_value_api_bias");
        }
    }
    if total >= 8 && session_span_secs >= 90 && repeated_ratio_percent >= 70 && distinct_routes <= 2
    {
        score += 20;
        flags.push("low_and_slow");
    }
    if let Some(jitter_ms) = jitter_ms {
        if total >= 6 && jitter_ms <= 250 {
            score += 20;
            flags.push("mechanical_intervals");
        } else if total >= 6 && jitter_ms <= 500 {
            score += 10;
            flags.push("low_jitter");
        }
    }
    if broad_navigation_context {
        score = score.saturating_sub(25);
        flags.push("broad_navigation_context");
    }

    BehaviorAssessment {
        identity,
        score: score.min(100),
        dominant_route: Some(dominant.0),
        distinct_routes,
        repeated_ratio_percent,
        document_repeated_ratio_percent,
        focused_document_route: document_dominant.map(|(route, _)| route),
        focused_api_route: api_dominant.map(|(route, _)| route),
        api_repeated_ratio_percent,
        jitter_ms,
        document_requests,
        api_requests,
        non_document_requests,
        recent_challenges,
        session_span_secs,
        flags,
    }
}

fn interval_jitter_ms(samples: &VecDeque<RequestSample>) -> Option<u64> {
    if samples.len() < 4 {
        return None;
    }
    let mut min_interval = u64::MAX;
    let mut max_interval = 0u64;
    let mut previous = None;
    for sample in samples.iter() {
        if let Some(prev) = previous {
            let delta = sample
                .at
                .duration_since(prev)
                .as_millis()
                .min(u128::from(u64::MAX)) as u64;
            min_interval = min_interval.min(delta);
            max_interval = max_interval.max(delta);
        }
        previous = Some(sample.at);
    }
    if min_interval == u64::MAX {
        None
    } else {
        Some(max_interval.saturating_sub(min_interval))
    }
}

fn request_identity(request: &UnifiedHttpRequest) -> Option<String> {
    let identity_state = request
        .get_metadata("network.identity_state")
        .map(String::as_str)
        .unwrap_or("unknown");

    if let Some(value) = cookie_value(request, "rwaf_fp") {
        return Some(format!("fp:{value}"));
    }
    if let Some(value) = request.get_header("x-browser-fingerprint-id") {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            return Some(format!("fp:{trimmed}"));
        }
    }
    if let Some(value) = passive_fingerprint_id(request) {
        return Some(format!("pfp:{value}"));
    }
    if let Some(value) = cookie_value(request, "rwaf_cc") {
        return Some(format!("cookie:{value}"));
    }
    if identity_state == "trusted_cdn_unresolved" {
        return None;
    }
    let ip = request.client_ip.as_deref()?.trim();
    if ip.is_empty() {
        return None;
    }
    let ua = request
        .get_header("user-agent")
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .unwrap_or("-");
    Some(format!("ipua:{ip}|{ua}"))
}

fn passive_fingerprint_id(request: &UnifiedHttpRequest) -> Option<String> {
    let fields = [
        request
            .get_header("user-agent")
            .map(String::as_str)
            .unwrap_or(""),
        request
            .get_header("sec-ch-ua")
            .map(String::as_str)
            .unwrap_or(""),
        request
            .get_header("sec-ch-ua-mobile")
            .map(String::as_str)
            .unwrap_or(""),
        request
            .get_header("sec-ch-ua-platform")
            .map(String::as_str)
            .unwrap_or(""),
        request
            .get_header("accept-language")
            .map(String::as_str)
            .unwrap_or(""),
        request
            .get_header("accept-encoding")
            .map(String::as_str)
            .unwrap_or(""),
        request
            .get_header("tls-hash")
            .map(String::as_str)
            .unwrap_or(""),
    ];
    if fields.iter().all(|value| value.trim().is_empty()) {
        return None;
    }
    let seed = fields.join("|");
    let mut hasher = Sha256::new();
    hasher.update(seed.as_bytes());
    Some(
        format!("{:x}", hasher.finalize())
            .chars()
            .take(24)
            .collect(),
    )
}

fn is_high_value_route(route: &str) -> bool {
    let route = route.to_ascii_lowercase();
    [
        "/login",
        "/signin",
        "/signup",
        "/register",
        "/auth",
        "/search",
        "/query",
        "/captcha",
        "/verify",
        "/otp",
        "/checkout",
        "/order",
        "/pay",
        "/submit",
        "/detail",
        "/product",
        "/item",
        "/cart",
        "/user",
        "/account",
    ]
    .iter()
    .any(|segment| route.contains(segment))
}

fn request_kind(request: &UnifiedHttpRequest) -> RequestKind {
    if let Some(kind) = request
        .get_metadata("l7.cc.request_kind")
        .map(String::as_str)
    {
        return match kind {
            "document" => RequestKind::Document,
            "static" => RequestKind::Static,
            "api" => RequestKind::Api,
            _ => RequestKind::Other,
        };
    }

    let path = request_path(&request.uri).to_ascii_lowercase();
    let accept = request
        .get_header("accept")
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_default();
    let sec_fetch_dest = request
        .get_header("sec-fetch-dest")
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_default();
    let content_type = request
        .get_header("content-type")
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_default();
    let x_requested_with = request
        .get_header("x-requested-with")
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_default();

    if sec_fetch_dest == "document"
        || accept.contains("text/html")
        || path == "/"
        || path.ends_with(".html")
        || path.ends_with(".htm")
    {
        return RequestKind::Document;
    }

    if sec_fetch_dest == "script"
        || sec_fetch_dest == "style"
        || sec_fetch_dest == "image"
        || sec_fetch_dest == "font"
        || path.ends_with(".js")
        || path.ends_with(".css")
        || path.ends_with(".png")
        || path.ends_with(".jpg")
        || path.ends_with(".jpeg")
        || path.ends_with(".gif")
        || path.ends_with(".svg")
        || path.ends_with(".ico")
        || path.ends_with(".webp")
        || path.ends_with(".woff")
        || path.ends_with(".woff2")
    {
        return RequestKind::Static;
    }

    if path.starts_with("/api/")
        || accept.contains("application/json")
        || content_type.contains("application/json")
        || x_requested_with == "xmlhttprequest"
    {
        return RequestKind::Api;
    }

    RequestKind::Other
}

fn build_behavior_response(
    request: &UnifiedHttpRequest,
    status_code: u16,
    title: &str,
    reason: &str,
) -> CustomHttpResponse {
    let accept = request
        .get_header("accept")
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_default();
    let html = accept.contains("text/html") || accept.contains("application/xhtml+xml");
    if html {
        CustomHttpResponse {
            status_code,
            headers: vec![
                ("content-type".to_string(), "text/html; charset=utf-8".to_string()),
                ("cache-control".to_string(), "no-store".to_string()),
                ("retry-after".to_string(), "15".to_string()),
                ("x-rust-waf-behavior".to_string(), "active".to_string()),
            ],
            body: format!(
                "<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>{}</title></head><body><h1>{}</h1><p>检测到访问行为异常，请稍后再试。</p><p><code>{}</code></p></body></html>",
                escape_html(title),
                escape_html(title),
                escape_html(reason),
            )
            .into_bytes(),
            tarpit: None,
            random_status: None,
        }
    } else {
        CustomHttpResponse {
            status_code,
            headers: vec![
                (
                    "content-type".to_string(),
                    "text/plain; charset=utf-8".to_string(),
                ),
                ("cache-control".to_string(), "no-store".to_string()),
                ("retry-after".to_string(), "15".to_string()),
                ("x-rust-waf-behavior".to_string(), "active".to_string()),
            ],
            body: format!("{title}: {reason}").into_bytes(),
            tarpit: None,
            random_status: None,
        }
    }
}

fn request_path(uri: &str) -> &str {
    uri.split('?').next().unwrap_or(uri)
}

fn normalized_route_path(path: &str) -> String {
    let trimmed = path.trim();
    if trimmed.is_empty() || trimmed == "/" {
        "/".to_string()
    } else {
        trimmed.trim_end_matches('/').to_string()
    }
}

fn cookie_value<'a>(request: &'a UnifiedHttpRequest, name: &str) -> Option<&'a str> {
    request.get_header("cookie").and_then(|value| {
        value.split(';').find_map(|item| {
            let (key, value) = item.trim().split_once('=')?;
            (key.trim() == name).then_some(value.trim())
        })
    })
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::HttpVersion;

    fn request(method: &str, uri: &str, accept: &str) -> UnifiedHttpRequest {
        let mut request =
            UnifiedHttpRequest::new(HttpVersion::Http1_1, method.to_string(), uri.to_string());
        request.set_client_ip("203.0.113.10".to_string());
        request.add_header("host".to_string(), "example.com".to_string());
        request.add_header("accept".to_string(), accept.to_string());
        request.add_header("user-agent".to_string(), "MobileSafari".to_string());
        request
    }

    #[tokio::test]
    async fn repeated_document_requests_trigger_behavior_response() {
        let guard = L7BehaviorGuard::new();
        let mut last = None;
        for _ in 0..6 {
            let mut request = request("GET", "/", "text/html");
            request.add_metadata("l7.cc.request_kind".to_string(), "document".to_string());
            request.add_metadata("l7.cc.route".to_string(), "/".to_string());
            last = guard.inspect_request(&mut request).await;
        }
        assert!(last.is_some());
    }

    #[tokio::test]
    async fn mixed_navigation_keeps_behavior_score_low() {
        let guard = L7BehaviorGuard::new();
        let mut doc = request("GET", "/", "text/html");
        doc.add_metadata("l7.cc.request_kind".to_string(), "document".to_string());
        doc.add_metadata("l7.cc.route".to_string(), "/".to_string());
        assert!(guard.inspect_request(&mut doc).await.is_none());

        let mut js = request("GET", "/app.js", "*/*");
        js.add_metadata("l7.cc.request_kind".to_string(), "static".to_string());
        js.add_metadata("l7.cc.route".to_string(), "/app.js".to_string());
        assert!(guard.inspect_request(&mut js).await.is_none());

        let mut api = request("GET", "/api/feed", "application/json");
        api.add_metadata("l7.cc.request_kind".to_string(), "api".to_string());
        api.add_metadata("l7.cc.route".to_string(), "/api/feed".to_string());
        assert!(guard.inspect_request(&mut api).await.is_none());
        assert!(
            api.get_metadata("l7.behavior.score")
                .and_then(|value| value.parse::<u32>().ok())
                .unwrap_or_default()
                < CHALLENGE_SCORE
        );
    }

    #[tokio::test]
    async fn repeated_document_refreshes_with_sparse_assets_trigger_challenge() {
        let guard = L7BehaviorGuard::new();
        let mut last = None;
        for index in 0..8 {
            let mut doc = request("GET", "/", "text/html");
            doc.add_metadata("l7.cc.request_kind".to_string(), "document".to_string());
            doc.add_metadata("l7.cc.route".to_string(), "/".to_string());
            last = guard.inspect_request(&mut doc).await;

            if index % 2 == 0 {
                let mut favicon = request("GET", "/favicon.ico", "*/*");
                favicon.add_metadata("l7.cc.request_kind".to_string(), "static".to_string());
                favicon.add_metadata("l7.cc.route".to_string(), "/favicon.ico".to_string());
                let _ = guard.inspect_request(&mut favicon).await;
            }
        }

        assert!(last.is_some());
    }

    #[tokio::test]
    async fn repeated_full_page_reloads_with_many_assets_trigger_challenge() {
        let guard = L7BehaviorGuard::new();
        let mut last = None;

        for _cycle in 0..4 {
            let mut doc = request("GET", "/article.html", "text/html");
            doc.add_metadata("l7.cc.request_kind".to_string(), "document".to_string());
            doc.add_metadata("l7.cc.route".to_string(), "/article.html".to_string());
            last = guard.inspect_request(&mut doc).await;

            for asset in 0..12 {
                let mut static_request = request("GET", &format!("/static/{asset}.js"), "*/*");
                static_request.add_metadata("l7.cc.request_kind".to_string(), "static".to_string());
                static_request
                    .add_metadata("l7.cc.route".to_string(), format!("/static/{asset}.js"));
                let _ = guard.inspect_request(&mut static_request).await;
            }
        }

        assert!(last.is_some());
    }

    #[tokio::test]
    async fn broad_navigation_with_many_assets_stays_below_challenge() {
        let guard = L7BehaviorGuard::new();

        for page in 0..3 {
            let mut doc = request(
                "GET",
                "/wp-admin/edit-tags.php?taxonomy=category",
                "text/html",
            );
            doc.add_header("sec-fetch-dest".to_string(), "document".to_string());
            doc.add_metadata("l7.cc.request_kind".to_string(), "document".to_string());
            doc.add_metadata(
                "l7.cc.route".to_string(),
                "/wp-admin/edit-tags.php".to_string(),
            );
            assert!(guard.inspect_request(&mut doc).await.is_none());

            for asset in 0..32 {
                let mut req = request("GET", &format!("/wp-admin/load-{page}-{asset}.css"), "*/*");
                req.add_header("sec-fetch-dest".to_string(), "style".to_string());
                req.add_metadata("l7.cc.request_kind".to_string(), "static".to_string());
                req.add_metadata(
                    "l7.cc.route".to_string(),
                    format!("/wp-admin/load-{page}-{asset}.css"),
                );
                assert!(guard.inspect_request(&mut req).await.is_none());
            }

            let mut api = request("POST", "/admin/async/state", "application/json");
            api.add_header(
                "content-type".to_string(),
                "application/json; charset=utf-8".to_string(),
            );
            api.add_header("x-requested-with".to_string(), "XMLHttpRequest".to_string());
            api.add_metadata("l7.cc.request_kind".to_string(), "api".to_string());
            api.add_metadata("l7.cc.route".to_string(), "/admin/async/state".to_string());
            assert!(guard.inspect_request(&mut api).await.is_none());
        }

        let mut summary = request("GET", "/wp-admin/tools.php", "text/html");
        summary.add_header("sec-fetch-dest".to_string(), "document".to_string());
        summary.add_metadata("l7.cc.request_kind".to_string(), "document".to_string());
        summary.add_metadata("l7.cc.route".to_string(), "/wp-admin/tools.php".to_string());
        let _ = guard.inspect_request(&mut summary).await;

        let score = summary
            .get_metadata("l7.behavior.score")
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or_default();
        assert!(score < CHALLENGE_SCORE, "unexpected score {score}");
    }

    #[tokio::test]
    async fn repeated_challenges_escalate_to_block_and_persist() {
        let guard = L7BehaviorGuard::new();
        let mut actions = Vec::new();
        let mut persisted = Vec::new();

        for _ in 0..8 {
            let mut request = request("GET", "/", "text/html");
            request.add_metadata("l7.cc.request_kind".to_string(), "document".to_string());
            request.add_metadata("l7.cc.route".to_string(), "/".to_string());
            let result = guard.inspect_request(&mut request).await;
            actions.push(
                request
                    .get_metadata("l7.behavior.action")
                    .cloned()
                    .unwrap_or_default(),
            );
            persisted.push(result.map(|item| item.persist_blocked_ip).unwrap_or(false));
        }

        assert!(actions.iter().any(|action| action == "challenge"));
        assert!(actions.iter().any(|action| action == "block"));
        assert!(persisted.iter().any(|flag| *flag));
    }

    #[test]
    fn snapshot_profiles_excludes_idle_identities() {
        let guard = L7BehaviorGuard::new();
        let stale_unix = unix_timestamp() - (ACTIVE_PROFILE_IDLE_SECS + 5);
        let stale_window = BehaviorWindow::new();
        {
            let mut samples = stale_window
                .samples
                .lock()
                .expect("behavior window lock poisoned");
            samples.push_back(RequestSample {
                route: "/stale".to_string(),
                kind: RequestKind::Document,
                client_ip: Some("203.0.113.10".to_string()),
                at: Instant::now(),
            });
        }
        stale_window
            .last_seen_unix
            .store(stale_unix, Ordering::Relaxed);
        guard.buckets.insert("fp:stale".to_string(), stale_window);

        let fresh_window = BehaviorWindow::new();
        {
            let mut samples = fresh_window
                .samples
                .lock()
                .expect("behavior window lock poisoned");
            samples.push_back(RequestSample {
                route: "/fresh".to_string(),
                kind: RequestKind::Document,
                client_ip: Some("203.0.113.11".to_string()),
                at: Instant::now(),
            });
        }
        guard.buckets.insert("fp:fresh".to_string(), fresh_window);

        let profiles = guard.snapshot_profiles(16);
        assert!(profiles
            .iter()
            .any(|profile| profile.identity == "fp:fresh"));
        assert!(!profiles
            .iter()
            .any(|profile| profile.identity == "fp:stale"));
    }
}
