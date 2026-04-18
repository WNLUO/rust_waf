use super::*;

#[derive(Default)]
struct NodeAggregate {
    ingress_requests: u64,
    blocked_requests: u64,
    total_bytes: u64,
    last_seen_at: i64,
}

#[derive(Default)]
struct FlowAggregate {
    request_count: u64,
    bytes: u64,
    latency_sum_ms: u64,
    latency_samples: u64,
    last_seen_at: i64,
}

pub(super) fn build_snapshot_from_observations(
    window_seconds: u32,
    now_ms: i64,
    observations: Vec<TrafficObservation>,
    geo_cache: &DashMap<String, GeoNode>,
    origin_node: TrafficMapNodeSnapshot,
) -> TrafficMapSnapshot {
    let mut node_aggregates: BTreeMap<String, NodeAggregate> = BTreeMap::new();
    let mut flow_aggregates: BTreeMap<(String, &'static str, &'static str), FlowAggregate> =
        BTreeMap::new();

    for observation in &observations {
        let Some(node) = geo_cache.get(&observation.source_ip) else {
            continue;
        };
        let node_key = node.id.to_string();
        let node_entry = node_aggregates.entry(node_key.clone()).or_default();
        if observation.direction == TrafficDirection::Ingress {
            node_entry.ingress_requests = node_entry.ingress_requests.saturating_add(1);
            if observation.decision == TrafficDecision::Block {
                node_entry.blocked_requests = node_entry.blocked_requests.saturating_add(1);
            }
        }
        node_entry.total_bytes = node_entry.total_bytes.saturating_add(observation.bytes);
        node_entry.last_seen_at = node_entry.last_seen_at.max(observation.timestamp_ms);

        let flow_entry = flow_aggregates
            .entry((
                node_key,
                observation.direction.as_str(),
                observation.decision.as_str(),
            ))
            .or_default();
        flow_entry.request_count = flow_entry.request_count.saturating_add(1);
        flow_entry.bytes = flow_entry.bytes.saturating_add(observation.bytes);
        if let Some(latency_ms) = observation.latency_ms {
            flow_entry.latency_sum_ms = flow_entry.latency_sum_ms.saturating_add(latency_ms);
            flow_entry.latency_samples = flow_entry.latency_samples.saturating_add(1);
        }
        flow_entry.last_seen_at = flow_entry.last_seen_at.max(observation.timestamp_ms);
    }

    let window_ms = f64::from(window_seconds) * 1_000.0;
    let mut nodes = Vec::new();
    let mut peak_bandwidth_mbps = 0.0_f64;

    for (node_id, aggregate) in &node_aggregates {
        let Some(node) = geo_cache.iter().find(|item| item.value().id == *node_id) else {
            continue;
        };
        let bandwidth_mbps =
            ((aggregate.total_bytes as f64) * 8.0 / 1_000_000.0) / (window_ms / 1_000.0);
        peak_bandwidth_mbps = peak_bandwidth_mbps.max(bandwidth_mbps);
        nodes.push(TrafficMapNodeSnapshot {
            id: node.value().id.to_string(),
            name: node.value().name.to_string(),
            region: node.value().region.to_string(),
            role: "cdn".to_string(),
            lat: Some(node.value().lat),
            lng: Some(node.value().lng),
            country_code: node.value().country_code.clone(),
            country_name: node.value().country_name.clone(),
            geo_scope: node.value().geo_scope.clone(),
            traffic_weight: clamp_f64(
                node.value().traffic_weight
                    + (aggregate.ingress_requests as f64 / 12.0)
                    + (bandwidth_mbps / 25.0),
                0.2,
                1.6,
            ),
            request_count: aggregate.ingress_requests,
            blocked_count: aggregate.blocked_requests,
            bandwidth_mbps,
            last_seen_at: aggregate.last_seen_at,
        });
    }

    nodes.sort_by(|left, right| {
        right
            .bandwidth_mbps
            .partial_cmp(&left.bandwidth_mbps)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let mut flows = Vec::new();
    let mut allowed_flow_count = 0_u32;
    let mut blocked_flow_count = 0_u32;

    for ((node_id, direction, decision), aggregate) in flow_aggregates {
        if direction == "ingress" && decision == "allow" {
            allowed_flow_count = allowed_flow_count.saturating_add(1);
        }
        if direction == "ingress" && decision == "block" {
            blocked_flow_count = blocked_flow_count.saturating_add(1);
        }

        flows.push(TrafficMapFlowSnapshot {
            id: format!("{node_id}-{direction}-{decision}"),
            node_id,
            direction: direction.to_string(),
            decision: decision.to_string(),
            request_count: aggregate.request_count,
            bytes: aggregate.bytes,
            bandwidth_mbps: ((aggregate.bytes as f64) * 8.0 / 1_000_000.0) / (window_ms / 1_000.0),
            average_latency_ms: if aggregate.latency_samples == 0 {
                0
            } else {
                aggregate.latency_sum_ms / aggregate.latency_samples
            },
            last_seen_at: aggregate.last_seen_at,
        });
    }

    flows.sort_by(|left, right| {
        right
            .bandwidth_mbps
            .partial_cmp(&left.bandwidth_mbps)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let total_ingress_requests = flows
        .iter()
        .filter(|flow| flow.direction == "ingress")
        .map(|flow| flow.request_count)
        .sum::<u64>();

    TrafficMapSnapshot {
        scope: "global".to_string(),
        window_seconds,
        generated_at: now_ms,
        origin_node,
        nodes,
        flows,
        active_node_count: node_aggregates.len() as u32,
        peak_bandwidth_mbps,
        allowed_flow_count,
        blocked_flow_count,
        live_traffic_score: clamp_f64(
            (total_ingress_requests as f64 / 16.0) + (peak_bandwidth_mbps / 30.0),
            0.0,
            9.9,
        ),
    }
}
