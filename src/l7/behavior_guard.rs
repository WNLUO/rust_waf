use crate::core::{CustomHttpResponse, InspectionLayer, InspectionResult};
use crate::protocol::UnifiedHttpRequest;
use dashmap::DashMap;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const BEHAVIOR_WINDOW_SECS: u64 = 120;
const MAX_SAMPLES_PER_IDENTITY: usize = 48;
const CLEANUP_EVERY_REQUESTS: u64 = 512;
const CHALLENGE_SCORE: u32 = 60;
const BLOCK_SCORE: u32 = 90;
const DELAY_SCORE: u32 = 35;
const DELAY_MS: u64 = 250;

#[derive(Debug)]
pub struct L7BehaviorGuard {
    buckets: DashMap<String, BehaviorWindow>,
    request_sequence: AtomicU64,
}

#[derive(Debug)]
struct BehaviorWindow {
    samples: Mutex<VecDeque<RequestSample>>,
    last_seen_unix: AtomicI64,
}

#[derive(Debug, Clone)]
struct RequestSample {
    route: String,
    kind: RequestKind,
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
    jitter_ms: Option<u64>,
    document_requests: usize,
    non_document_requests: usize,
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
        let now = Instant::now();
        let unix_now = unix_timestamp();
        let window = Duration::from_secs(BEHAVIOR_WINDOW_SECS);
        let assessment = self.observe_and_assess(&identity, route, kind, now, unix_now, window);

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
            "l7.behavior.document_requests".to_string(),
            assessment.document_requests.to_string(),
        );
        request.add_metadata(
            "l7.behavior.non_document_requests".to_string(),
            assessment.non_document_requests.to_string(),
        );
        if let Some(route) = assessment.dominant_route.as_ref() {
            request.add_metadata("l7.behavior.dominant_route".to_string(), route.clone());
        }
        if let Some(jitter_ms) = assessment.jitter_ms {
            request.add_metadata(
                "l7.behavior.interval_jitter_ms".to_string(),
                jitter_ms.to_string(),
            );
        }

        self.maybe_cleanup(unix_now);

        if assessment.score >= BLOCK_SCORE {
            request.add_metadata("l7.behavior.action".to_string(), "block".to_string());
            let reason = format!(
                "l7 behavior guard blocked suspicious session: score={} repeated_ratio={} distinct_routes={} dominant_route={}",
                assessment.score,
                assessment.repeated_ratio_percent,
                assessment.distinct_routes,
                assessment.dominant_route.as_deref().unwrap_or("*")
            );
            return Some(InspectionResult::respond(
                InspectionLayer::L7,
                reason.clone(),
                build_behavior_response(request, 429, "行为异常，请稍后重试", &reason),
            ));
        }

        if assessment.score >= CHALLENGE_SCORE {
            request.add_metadata("l7.behavior.action".to_string(), "challenge".to_string());
            let reason = format!(
                "l7 behavior guard challenged suspicious session: score={} repeated_ratio={} distinct_routes={} dominant_route={}",
                assessment.score,
                assessment.repeated_ratio_percent,
                assessment.distinct_routes,
                assessment.dominant_route.as_deref().unwrap_or("*")
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
        now: Instant,
        unix_now: i64,
        window: Duration,
    ) -> BehaviorAssessment {
        let mut entry = self
            .buckets
            .entry(identity.to_string())
            .or_insert_with(BehaviorWindow::new);
        entry.observe_and_assess(identity.to_string(), route, kind, now, unix_now, window)
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
}

impl BehaviorWindow {
    fn new() -> Self {
        Self {
            samples: Mutex::new(VecDeque::new()),
            last_seen_unix: AtomicI64::new(unix_timestamp()),
        }
    }

    fn observe_and_assess(
        &mut self,
        identity: String,
        route: String,
        kind: RequestKind,
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
            at: now,
        });
        while samples.len() > MAX_SAMPLES_PER_IDENTITY {
            samples.pop_front();
        }
        self.last_seen_unix.store(unix_now, Ordering::Relaxed);

        let mut route_counts: HashMap<&str, usize> = HashMap::new();
        let mut document_requests = 0usize;
        let mut non_document_requests = 0usize;
        for sample in samples.iter() {
            *route_counts.entry(sample.route.as_str()).or_insert(0) += 1;
            if matches!(sample.kind, RequestKind::Document) {
                document_requests += 1;
            } else {
                non_document_requests += 1;
            }
        }
        let total = samples.len().max(1);
        let dominant = route_counts
            .iter()
            .max_by_key(|(_, count)| **count)
            .map(|(route, count)| ((*route).to_string(), *count))
            .unwrap_or_else(|| (route, 1));
        let repeated_ratio_percent = ((dominant.1 * 100) / total) as u32;
        let distinct_routes = route_counts.len();
        let jitter_ms = interval_jitter_ms(&samples);

        let mut score = 0u32;
        if total >= 8 && repeated_ratio_percent >= 85 {
            score += 45;
        } else if total >= 6 && repeated_ratio_percent >= 70 {
            score += 25;
        }
        if total >= 10 && distinct_routes <= 2 {
            score += 20;
        }
        if document_requests >= 4 && non_document_requests == 0 {
            score += 25;
        } else if document_requests >= 3 && non_document_requests <= 1 {
            score += 10;
        }
        if matches!(kind, RequestKind::Api) && total >= 6 && distinct_routes <= 2 {
            score += 15;
        }
        if let Some(jitter_ms) = jitter_ms {
            if total >= 6 && jitter_ms <= 250 {
                score += 25;
            } else if total >= 6 && jitter_ms <= 500 {
                score += 10;
            }
        }

        BehaviorAssessment {
            identity,
            score: score.min(100),
            dominant_route: Some(dominant.0),
            distinct_routes,
            repeated_ratio_percent,
            jitter_ms,
            document_requests,
            non_document_requests,
        }
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
    if let Some(value) = cookie_value(request, "rwaf_cc") {
        return Some(format!("cookie:{value}"));
    }
    if let Some(value) = request.get_header("x-browser-fingerprint-id") {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            return Some(format!("fp:{trimmed}"));
        }
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

fn request_kind(request: &UnifiedHttpRequest) -> RequestKind {
    match request
        .get_metadata("l7.cc.request_kind")
        .map(String::as_str)
    {
        Some("document") => RequestKind::Document,
        Some("static") => RequestKind::Static,
        Some("api") => RequestKind::Api,
        _ => RequestKind::Other,
    }
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
}
