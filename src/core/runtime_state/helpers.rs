use super::*;

pub(super) fn protocol_stream_budget(configured: usize, defense_depth: &str) -> usize {
    let configured = configured.max(1);
    match defense_depth {
        "survival" => configured.min(8),
        "lean" => configured.min(24),
        "balanced" => configured.min(64),
        _ => configured,
    }
}

pub(super) fn defense_depth_is_stricter(left: DefenseDepth, right: DefenseDepth) -> bool {
    defense_depth_rank(left) > defense_depth_rank(right)
}

fn defense_depth_rank(depth: DefenseDepth) -> u8 {
    match depth {
        DefenseDepth::Full => 0,
        DefenseDepth::Balanced => 1,
        DefenseDepth::Lean => 2,
        DefenseDepth::Survival => 3,
    }
}

impl WafContext {
    pub(super) fn site_defense_depth(&self, site_id: &str) -> Option<DefenseDepth> {
        let entry = self.site_defense_buckets.get(site_id)?;
        let bucket = entry.lock().expect("site defense bucket lock poisoned");
        let now = unix_timestamp();
        if now.saturating_sub(bucket.window_start) > 75 {
            return None;
        }
        if bucket.hard_events >= 12 || bucket.soft_events.saturating_add(bucket.hard_events) >= 80 {
            return Some(DefenseDepth::Survival);
        }
        if bucket.hard_events >= 4 || bucket.soft_events.saturating_add(bucket.hard_events) >= 24 {
            return Some(DefenseDepth::Lean);
        }
        None
    }

    pub(super) fn route_defense_depth(&self, site_id: &str, route: &str) -> Option<DefenseDepth> {
        if route_defense_exempt(route) {
            return None;
        }
        let entry = self
            .route_defense_buckets
            .get(&route_defense_key(site_id, route))?;
        let bucket = entry.lock().expect("route defense bucket lock poisoned");
        let now = unix_timestamp();
        if now.saturating_sub(bucket.window_start) > 75 {
            return None;
        }
        route_defense_depth_for_counts(bucket.soft_events, bucket.hard_events)
    }

    pub(super) fn ensure_route_defense_capacity(&self, route_key: &str, window_start: i64) -> bool {
        if self.route_defense_buckets.contains_key(route_key)
            || self.route_defense_buckets.len() < MAX_ROUTE_DEFENSE_BUCKETS
        {
            return true;
        }

        let stale_before = window_start.saturating_sub(120);
        let stale_keys = self
            .route_defense_buckets
            .iter()
            .filter_map(|entry| {
                let bucket = entry
                    .value()
                    .lock()
                    .expect("route defense bucket lock poisoned");
                (bucket.window_start < stale_before).then(|| entry.key().clone())
            })
            .take(256)
            .collect::<Vec<_>>();
        for key in stale_keys {
            self.route_defense_buckets.remove(&key);
        }

        self.route_defense_buckets.len() < MAX_ROUTE_DEFENSE_BUCKETS
    }
}

pub(super) fn select_strictest_depth(
    left: Option<DefenseDepth>,
    right: Option<DefenseDepth>,
) -> Option<DefenseDepth> {
    match (left, right) {
        (Some(left), Some(right)) => {
            if defense_depth_is_stricter(left, right) {
                Some(left)
            } else {
                Some(right)
            }
        }
        (Some(depth), None) | (None, Some(depth)) => Some(depth),
        (None, None) => None,
    }
}

pub(super) fn apply_route_local_cc_tightening(
    request: &mut UnifiedHttpRequest,
    depth: DefenseDepth,
) {
    let (route_scale, host_scale, force_challenge) = match depth {
        DefenseDepth::Survival => (45, 70, true),
        DefenseDepth::Lean => (70, 85, false),
        DefenseDepth::Full | DefenseDepth::Balanced => return,
    };
    set_min_percent_metadata(request, "ai.cc.route_threshold_scale_percent", route_scale);
    set_min_percent_metadata(request, "ai.cc.host_threshold_scale_percent", host_scale);
    request.add_metadata(
        "runtime.route.cc_threshold_scale_percent".to_string(),
        route_scale.to_string(),
    );
    if force_challenge {
        request.add_metadata("ai.cc.force_challenge".to_string(), "true".to_string());
    }
}

fn set_min_percent_metadata(request: &mut UnifiedHttpRequest, key: &str, value: u32) {
    let current = request
        .get_metadata(key)
        .and_then(|item| item.parse::<u32>().ok())
        .unwrap_or(100);
    if value < current {
        request.add_metadata(key.to_string(), value.to_string());
    }
}

pub(super) fn runtime_route_path(uri: &str) -> String {
    let path = uri.split('?').next().unwrap_or(uri).trim();
    let path = if path.is_empty() { "/" } else { path };
    let trimmed = if path != "/" {
        path.trim_end_matches('/')
    } else {
        path
    };
    if trimmed.len() <= 160 {
        trimmed.to_ascii_lowercase()
    } else {
        let digest = stable_hash_hex(trimmed);
        format!("route:{digest}")
    }
}

pub(super) fn route_defense_key(site_id: &str, route: &str) -> String {
    format!("{site_id}|{route}")
}

pub(super) fn split_route_defense_key(value: &str) -> Option<(String, String)> {
    let (site_id, route) = value.split_once('|')?;
    Some((site_id.to_string(), route.to_string()))
}

pub(super) fn route_defense_depth_for_counts(
    soft_events: u64,
    hard_events: u64,
) -> Option<DefenseDepth> {
    let total = soft_events.saturating_add(hard_events);
    if hard_events >= 5 || total >= 18 {
        return Some(DefenseDepth::Survival);
    }
    if hard_events >= 2 || total >= 8 {
        return Some(DefenseDepth::Lean);
    }
    None
}

pub(super) fn route_defense_confidence(
    total_events: u64,
    hard_events: u64,
    depth: DefenseDepth,
) -> u8 {
    let base = match depth {
        DefenseDepth::Survival => 82,
        DefenseDepth::Lean => 68,
        DefenseDepth::Full | DefenseDepth::Balanced => 50,
    };
    let hard_bonus = hard_events.saturating_mul(3).min(12) as u8;
    let volume_bonus = total_events.saturating_sub(8).min(10) as u8;
    (base + hard_bonus + volume_bonus).min(100)
}

pub(super) fn compact_recommendation_key(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect::<String>()
        .split('_')
        .filter(|item| !item.is_empty())
        .collect::<Vec<_>>()
        .join("_")
        .chars()
        .take(96)
        .collect()
}

pub(super) fn route_defense_exempt(route: &str) -> bool {
    route == "/favicon.ico"
        || route == "/robots.txt"
        || route == "/sitemap.xml"
        || route.starts_with("/.well-known/")
        || route.starts_with("/assets/")
        || route.starts_with("/static/")
}

fn stable_hash_hex(value: &str) -> String {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    value.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}
