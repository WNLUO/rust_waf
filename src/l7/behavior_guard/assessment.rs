use super::request_utils::is_high_value_route;
use super::*;
use std::collections::{HashMap, HashSet, VecDeque};

pub(super) fn assess_samples(
    identity: String,
    samples: &VecDeque<RequestSample>,
    now: Instant,
    recent_challenges: usize,
) -> BehaviorAssessment {
    let mut route_counts: HashMap<&str, usize> = HashMap::new();
    let mut document_route_counts: HashMap<&str, usize> = HashMap::new();
    let mut api_route_counts: HashMap<&str, usize> = HashMap::new();
    let mut client_ip_counts: HashMap<&str, usize> = HashMap::new();
    let mut user_agent_counts: HashMap<&str, usize> = HashMap::new();
    let mut header_signature_counts: HashMap<&str, usize> = HashMap::new();
    let mut api_requests = 0usize;
    let mut document_requests = 0usize;
    let mut non_document_requests = 0usize;
    for sample in samples.iter() {
        *route_counts.entry(sample.route.as_str()).or_insert(0) += 1;
        if let Some(client_ip) = sample.client_ip.as_deref() {
            *client_ip_counts.entry(client_ip).or_insert(0) += 1;
        }
        if let Some(user_agent) = sample.user_agent.as_deref() {
            *user_agent_counts.entry(user_agent).or_insert(0) += 1;
        }
        if let Some(header_signature) = sample.header_signature.as_deref() {
            *header_signature_counts.entry(header_signature).or_insert(0) += 1;
        }
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
    let distinct_client_ips = samples
        .iter()
        .filter_map(|sample| sample.client_ip.as_deref())
        .collect::<HashSet<_>>()
        .len();
    let distinct_user_agents = samples
        .iter()
        .filter_map(|sample| sample.user_agent.as_deref())
        .collect::<HashSet<_>>()
        .len();
    let distinct_header_signatures = samples
        .iter()
        .filter_map(|sample| sample.header_signature.as_deref())
        .collect::<HashSet<_>>()
        .len();
    let dominant_client_ip_count = client_ip_counts.values().copied().max().unwrap_or(0);
    let client_ip_repeated_ratio_percent = if distinct_client_ips == 0 {
        0
    } else {
        ((dominant_client_ip_count * 100) / total) as u32
    };
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
    if total >= 12
        && distinct_client_ips >= 5
        && repeated_ratio_percent >= 90
        && document_requests >= 8
        && document_repeated_ratio_percent >= 90
        && non_document_requests <= document_requests.saturating_div(2).max(1)
        && session_span_secs <= 120
    {
        score += 75;
        flags.push("distributed_document_burst");
    } else if total >= 8
        && distinct_client_ips >= 4
        && repeated_ratio_percent >= 90
        && document_requests >= 6
        && document_repeated_ratio_percent >= 90
        && non_document_requests <= document_requests.saturating_div(2).max(1)
        && session_span_secs <= 60
    {
        score += 55;
        flags.push("distributed_document_probe");
    }
    if total >= 12
        && distinct_client_ips >= 4
        && api_requests >= 8
        && api_repeated_ratio_percent >= 85
        && distinct_routes <= 2
        && session_span_secs <= 90
    {
        score += 65;
        flags.push("distributed_api_burst");
    }
    if distinct_client_ips >= 4
        && client_ip_repeated_ratio_percent <= 40
        && repeated_ratio_percent >= 90
    {
        score += 15;
        flags.push("source_rotation");
    }
    if total >= 10
        && distinct_client_ips >= 4
        && distinct_user_agents >= 4
        && distinct_header_signatures <= 2
    {
        score += 20;
        flags.push("ua_pool_header_reuse");
    }
    if total >= 8
        && distinct_client_ips >= 4
        && document_requests >= 6
        && non_document_requests == 0
    {
        score += 25;
        flags.push("aggregate_document_without_assets");
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
    if total >= 8
        && distinct_client_ips <= 2
        && repeated_ratio_percent >= 90
        && document_requests >= 6
        && document_repeated_ratio_percent >= 90
        && non_document_requests <= document_requests.saturating_div(2).max(1)
    {
        score += 25;
        flags.push("single_source_document_loop");
    }
    if total >= 8
        && distinct_client_ips <= 2
        && repeated_ratio_percent >= 90
        && distinct_user_agents >= 4
    {
        score += 20;
        flags.push("single_source_identity_rotation");
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
        distinct_client_ips,
        distinct_user_agents,
        distinct_header_signatures,
        repeated_ratio_percent,
        client_ip_repeated_ratio_percent,
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
