use super::types::VisitorRouteSummary;
use std::collections::BTreeMap;

pub(super) fn compact_text(value: &str, limit: usize) -> String {
    let trimmed = value.trim().replace('\n', " ").replace('\r', " ");
    if trimmed.chars().count() <= limit {
        trimmed
    } else {
        format!("{}...", trimmed.chars().take(limit).collect::<String>())
    }
}

pub(super) fn visitor_priority_rank(value: &str) -> u8 {
    match value {
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

pub(super) fn stable_hash(value: &str) -> String {
    let mut hash = 1469598103934665603u64;
    for byte in value.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(1099511628211);
    }
    format!("{hash:016x}")
}

pub(super) fn top_routes(routes: &BTreeMap<String, u64>, limit: usize) -> Vec<VisitorRouteSummary> {
    let mut items = routes
        .iter()
        .map(|(route, count)| VisitorRouteSummary {
            route: route.clone(),
            count: *count,
        })
        .collect::<Vec<_>>();
    items.sort_by(|left, right| {
        right
            .count
            .cmp(&left.count)
            .then_with(|| left.route.cmp(&right.route))
    });
    items.truncate(limit);
    items
}
