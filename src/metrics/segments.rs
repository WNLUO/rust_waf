use super::ProxyMetricLabels;
use crate::locks::mutex_lock;
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::Mutex;

const MAX_PROXY_SEGMENT_ENTRIES: usize = 512;
const MAX_SEGMENT_COMPONENT_LEN: usize = 96;

#[derive(Debug, Clone, Default)]
pub(super) struct ProxyTrafficSegmentAccumulator {
    proxied_requests: u64,
    proxy_successes: u64,
    proxy_failures: u64,
    latency_micros_total: u64,
}

#[derive(Debug, Clone, Default)]
pub struct ProxyTrafficSegmentSnapshot {
    pub scope_type: String,
    pub scope_key: String,
    pub host: Option<String>,
    pub route: Option<String>,
    pub request_kind: String,
    pub proxied_requests: u64,
    pub proxy_successes: u64,
    pub proxy_failures: u64,
    pub average_proxy_latency_micros: u64,
}

#[derive(Debug, Clone, Copy)]
pub(super) enum ProxySegmentUpdate {
    Attempt { latency_micros: Option<u64> },
    Success { latency_micros: Option<u64> },
    Failure { latency_micros: Option<u64> },
}

#[derive(Debug, Clone, Copy)]
pub(super) enum ProxySegmentScope {
    Host,
    Route,
    HostRoute,
}

pub(super) fn update_segment_map(
    segments: &Mutex<HashMap<String, ProxyTrafficSegmentAccumulator>>,
    key: String,
    update: ProxySegmentUpdate,
) {
    let mut guard = mutex_lock(segments, "segment metrics");
    let key = bounded_segment_key(&key, guard.len());
    let entry = guard
        .entry(key)
        .or_insert_with(ProxyTrafficSegmentAccumulator::default);
    match update {
        ProxySegmentUpdate::Attempt { latency_micros } => {
            entry.proxied_requests = entry.proxied_requests.saturating_add(1);
            if let Some(value) = latency_micros {
                entry.latency_micros_total = entry.latency_micros_total.saturating_add(value);
            }
        }
        ProxySegmentUpdate::Success { latency_micros } => {
            entry.proxy_successes = entry.proxy_successes.saturating_add(1);
            if let Some(value) = latency_micros {
                entry.latency_micros_total = entry.latency_micros_total.saturating_add(value);
            }
        }
        ProxySegmentUpdate::Failure { latency_micros } => {
            entry.proxy_failures = entry.proxy_failures.saturating_add(1);
            if let Some(value) = latency_micros {
                entry.latency_micros_total = entry.latency_micros_total.saturating_add(value);
            }
        }
    }
}

pub(super) fn segment_snapshots(
    segments: &Mutex<HashMap<String, ProxyTrafficSegmentAccumulator>>,
    scope: ProxySegmentScope,
    limit: usize,
) -> Vec<ProxyTrafficSegmentSnapshot> {
    let guard = mutex_lock(segments, "segment metrics");
    let mut snapshots = guard
        .iter()
        .map(|(key, value)| build_segment_snapshot(scope, key, value))
        .collect::<Vec<_>>();
    snapshots.sort_by(|left, right| {
        right
            .proxied_requests
            .cmp(&left.proxied_requests)
            .then(right.proxy_failures.cmp(&left.proxy_failures))
            .then(
                right
                    .average_proxy_latency_micros
                    .cmp(&left.average_proxy_latency_micros),
            )
            .then(left.scope_key.cmp(&right.scope_key))
    });
    snapshots.truncate(limit);
    snapshots
}

pub(super) fn host_segment_key(labels: &ProxyMetricLabels) -> String {
    format!("{}|{}", labels.host, labels.request_kind)
}

pub(super) fn route_segment_key(labels: &ProxyMetricLabels) -> String {
    format!("{}|{}", labels.route, labels.request_kind)
}

pub(super) fn host_route_segment_key(labels: &ProxyMetricLabels) -> String {
    format!("{}|{}|{}", labels.host, labels.route, labels.request_kind)
}

fn bounded_segment_key(key: &str, current_len: usize) -> String {
    let normalized = normalize_segment_key(key);
    if current_len < MAX_PROXY_SEGMENT_ENTRIES {
        return normalized;
    }

    let mut parts = normalized.split('|').collect::<Vec<_>>();
    if parts.is_empty() {
        return overflow_segment_key("", "", "other");
    }
    let request_kind = parts.pop().unwrap_or("other");
    let host = parts.first().copied().unwrap_or_default();
    let route = parts.get(1).copied().unwrap_or_default();
    overflow_segment_key(host, route, request_kind)
}

fn normalize_segment_key(key: &str) -> String {
    key.split('|')
        .map(compact_segment_component)
        .collect::<Vec<_>>()
        .join("|")
}

fn compact_segment_component(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.len() <= MAX_SEGMENT_COMPONENT_LEN {
        return trimmed.to_string();
    }

    let mut hasher = DefaultHasher::new();
    trimmed.hash(&mut hasher);
    let hash = hasher.finish();
    let prefix_len = MAX_SEGMENT_COMPONENT_LEN.saturating_sub(18);
    let prefix = trimmed.chars().take(prefix_len).collect::<String>();
    format!("{prefix}:seg-{hash:016x}")
}

fn overflow_segment_key(host: &str, route: &str, request_kind: &str) -> String {
    let mut hasher = DefaultHasher::new();
    host.hash(&mut hasher);
    route.hash(&mut hasher);
    request_kind.hash(&mut hasher);
    format!("__overflow__|{:03}|{}", hasher.finish() % 128, request_kind)
}

fn build_segment_snapshot(
    scope: ProxySegmentScope,
    key: &str,
    value: &ProxyTrafficSegmentAccumulator,
) -> ProxyTrafficSegmentSnapshot {
    let (host, route, request_kind) = match scope {
        ProxySegmentScope::Host => {
            let mut parts = key.splitn(2, '|');
            let host = parts.next().unwrap_or_default().to_string();
            let request_kind = parts.next().unwrap_or("other").to_string();
            (Some(host), None, request_kind)
        }
        ProxySegmentScope::Route => {
            let mut parts = key.splitn(2, '|');
            let route = parts.next().unwrap_or_default().to_string();
            let request_kind = parts.next().unwrap_or("other").to_string();
            (None, Some(route), request_kind)
        }
        ProxySegmentScope::HostRoute => {
            let mut parts = key.splitn(3, '|');
            let host = parts.next().unwrap_or_default().to_string();
            let route = parts.next().unwrap_or_default().to_string();
            let request_kind = parts.next().unwrap_or("other").to_string();
            (Some(host), Some(route), request_kind)
        }
    };
    let successes = value.proxy_successes.max(1);
    ProxyTrafficSegmentSnapshot {
        scope_type: match scope {
            ProxySegmentScope::Host => "host".to_string(),
            ProxySegmentScope::Route => "route".to_string(),
            ProxySegmentScope::HostRoute => "host_route".to_string(),
        },
        scope_key: key.to_string(),
        host,
        route,
        request_kind,
        proxied_requests: value.proxied_requests,
        proxy_successes: value.proxy_successes,
        proxy_failures: value.proxy_failures,
        average_proxy_latency_micros: if value.proxy_successes == 0 {
            0
        } else {
            value.latency_micros_total / successes
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn segment_keys_are_folded_when_cardinality_grows_too_high() {
        let key = bounded_segment_key(
            "very-long-host.example.com|/hot/route|api",
            MAX_PROXY_SEGMENT_ENTRIES,
        );
        assert!(key.starts_with("__overflow__|"));
        assert!(key.ends_with("|api"));
    }

    #[test]
    fn long_segment_components_are_compacted() {
        let compacted =
            normalize_segment_key(&format!("{}|{}|api", "h".repeat(256), "r".repeat(256)));
        assert!(compacted.len() < 256);
        assert!(compacted.contains(":seg-"));
    }
}
