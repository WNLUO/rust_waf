use super::metrics::build_metrics_response;
use super::state::ApiState;
use super::types::{
    BlockedIpResponse, BlockedIpsResponse, L4StatsResponse, L7StatsResponse, MetricsResponse,
    SecurityEventResponse, SecurityEventsResponse, TrafficMapFlowResponse, TrafficMapNodeResponse,
    TrafficMapResponse,
};
use crate::core::WafContext;
use crate::storage::StorageRealtimeEvent;
use crate::storage::{
    BlockedIpQuery, BlockedIpSortField, EventSortField, SecurityEventQuery, SortDirection,
    StorageMetricsSummary,
};
use axum::{
    extract::{
        ws::{Message, WebSocket},
        Query, State, WebSocketUpgrade,
    },
    http::StatusCode,
    response::Response,
};
use serde::Serialize;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::broadcast;
use tokio::time::{self, Duration, MissedTickBehavior};

#[derive(Debug, serde::Deserialize, Default)]
pub(super) struct AdminWsQuery {
    ticket: Option<String>,
}

#[derive(Debug, Serialize)]
struct RealtimeEnvelope {
    topic: &'static str,
    payload: Value,
}

#[derive(Debug, Clone, Copy)]
struct RealtimePressurePolicy {
    fast_message_every_ticks: u64,
    periodic_message_every_ticks: u64,
    include_traffic_map_in_fast_path: bool,
    security_event_sample_rate: u64,
    traffic_event_sample_rate: u64,
}

#[derive(Debug, Serialize)]
pub(super) struct AdminWsTicketResponse {
    ticket: String,
    expires_at: i64,
}

#[derive(Default)]
pub(super) struct WsTicketStore {
    tickets: std::sync::Mutex<HashMap<String, i64>>,
}

impl WsTicketStore {
    const TTL_SECS: i64 = 30;

    pub(super) fn issue(&self) -> AdminWsTicketResponse {
        let mut ticket = random_ticket();
        let expires_at = unix_timestamp() + Self::TTL_SECS;
        let mut guard = self.tickets.lock().expect("ws_tickets mutex poisoned");

        while guard.contains_key(&ticket) {
            ticket = random_ticket();
        }
        guard.retain(|_, expires| *expires > unix_timestamp());
        guard.insert(ticket.clone(), expires_at);

        AdminWsTicketResponse { ticket, expires_at }
    }

    pub(super) fn consume(&self, ticket: &str) -> bool {
        let now = unix_timestamp();
        let mut guard = self.tickets.lock().expect("ws_tickets mutex poisoned");
        guard.retain(|_, expires| *expires > now);
        guard.remove(ticket).is_some_and(|expires| expires > now)
    }
}

pub(super) fn spawn_sampler(context: Arc<WafContext>, realtime_tx: broadcast::Sender<String>) {
    tokio::spawn(async move {
        let mut interval = time::interval(Duration::from_secs(1));
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let mut tick: u64 = 0;
        let mut cached_storage_summary = collect_storage_summary(context.as_ref()).await;

        loop {
            interval.tick().await;
            tick = tick.wrapping_add(1);
            let policy = realtime_policy(context.as_ref());

            // Refresh SQLite summary less frequently to avoid per-second DB pressure.
            if tick % policy.periodic_message_every_ticks == 1 {
                cached_storage_summary = collect_storage_summary(context.as_ref()).await;
            }

            if tick % policy.fast_message_every_ticks == 0 {
                if let Ok(messages) =
                    collect_fast_messages(context.as_ref(), cached_storage_summary.clone(), policy)
                        .await
                {
                    for message in messages {
                        let _ = realtime_tx.send(message);
                    }
                }
            }

            // Periodic full-list refresh heals missed deltas without hammering SQLite every second.
            if tick % policy.periodic_message_every_ticks == 0 {
                if let Ok(messages) = collect_periodic_messages(context.as_ref()).await {
                    for message in messages {
                        let _ = realtime_tx.send(message);
                    }
                }
            }
        }
    });
}

pub(super) fn spawn_storage_bridge(
    context: Arc<WafContext>,
    realtime_tx: broadcast::Sender<String>,
) {
    let Some(store) = context.sqlite_store.as_ref() else {
        return;
    };
    let mut storage_rx = store.subscribe_realtime();

    tokio::spawn(async move {
        let mut security_event_seq: u64 = 0;
        loop {
            let policy = realtime_policy(context.as_ref());
            let message = match storage_rx.recv().await {
                Ok(StorageRealtimeEvent::SecurityEvent(event)) => {
                    security_event_seq = security_event_seq.wrapping_add(1);
                    if should_sample_out(security_event_seq, policy.security_event_sample_rate)
                        && !is_high_value_security_event(&event)
                    {
                        continue;
                    }
                    serialize_message("security_event_delta", &SecurityEventResponse::from(event))
                }
                Ok(StorageRealtimeEvent::BlockedIpUpsert(entry)) => {
                    serialize_message("blocked_ip_upsert", &BlockedIpResponse::from(entry))
                }
                Ok(StorageRealtimeEvent::BlockedIpDeleted(id)) => {
                    serialize_message("blocked_ip_deleted", &serde_json::json!({ "id": id }))
                }
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => break,
            };

            if let Ok(payload) = message {
                let _ = realtime_tx.send(payload);
            }
        }
    });
}

pub(super) fn spawn_traffic_bridge(
    context: Arc<WafContext>,
    realtime_tx: broadcast::Sender<String>,
) {
    let mut traffic_rx = context.subscribe_traffic_realtime();

    tokio::spawn(async move {
        let mut traffic_seq: u64 = 0;
        loop {
            let policy = realtime_policy(context.as_ref());
            let event = match traffic_rx.recv().await {
                Ok(event) => event,
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => break,
            };
            traffic_seq = traffic_seq.wrapping_add(1);
            if should_sample_out(traffic_seq, policy.traffic_event_sample_rate)
                && !is_high_value_traffic_event(&event)
            {
                continue;
            }

            let enriched = context.enrich_traffic_realtime_event(event).await;
            if let Ok(payload) = serialize_message("traffic_event_delta", &enriched) {
                let _ = realtime_tx.send(payload);
            }
        }
    });
}

pub(super) async fn issue_admin_ws_ticket_handler(
    State(state): State<ApiState>,
) -> axum::Json<AdminWsTicketResponse> {
    axum::Json(state.ws_tickets.issue())
}

pub(super) async fn admin_ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<ApiState>,
    Query(query): Query<AdminWsQuery>,
) -> Result<Response, StatusCode> {
    if !query
        .ticket
        .as_deref()
        .is_some_and(|ticket| state.ws_tickets.consume(ticket))
    {
        return Err(StatusCode::UNAUTHORIZED);
    }

    Ok(ws.on_upgrade(move |socket| handle_socket(socket, state)))
}

async fn handle_socket(socket: WebSocket, state: ApiState) {
    let mut socket = socket;
    let mut realtime_rx = state.realtime_tx.subscribe();

    if let Ok(messages) = collect_messages(state.context.as_ref()).await {
        for payload in messages {
            if socket.send(Message::Text(payload)).await.is_err() {
                return;
            }
        }
    }

    let mut ping_interval = time::interval(Duration::from_secs(20));
    ping_interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            biased;

            incoming = socket.recv() => {
                match incoming {
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(Message::Ping(payload))) => {
                        if socket.send(Message::Pong(payload)).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(_)) => {}
                    Some(Err(_)) => break,
                }
            }
            outbound = realtime_rx.recv() => {
                match outbound {
                    Ok(payload) => {
                        if socket.send(Message::Text(payload)).await.is_err() {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
            _ = ping_interval.tick() => {
                if socket.send(Message::Ping(Vec::new())).await.is_err() {
                    break;
                }
            }
        }
    }
}

async fn collect_messages(context: &WafContext) -> anyhow::Result<Vec<String>> {
    let storage_summary = collect_storage_summary(context).await;
    let metrics = collect_metrics(context, storage_summary);
    let l4_stats = collect_l4_stats(context);
    let l7_stats = collect_l7_stats(context);
    let recent_events = collect_recent_events(context).await?;
    let recent_blocked_ips = collect_recent_blocked_ips(context).await?;
    let traffic_map = collect_traffic_map(context).await;

    Ok(vec![
        serialize_message("metrics", &metrics)?,
        serialize_message("l4_stats", &l4_stats)?,
        serialize_message("l7_stats", &l7_stats)?,
        serialize_message("recent_events", &recent_events)?,
        serialize_message("recent_blocked_ips", &recent_blocked_ips)?,
        serialize_message("traffic_map", &traffic_map)?,
    ])
}

async fn collect_fast_messages(
    context: &WafContext,
    storage_summary: Option<StorageMetricsSummary>,
    policy: RealtimePressurePolicy,
) -> anyhow::Result<Vec<String>> {
    let metrics = collect_metrics(context, storage_summary);
    let l4_stats = collect_l4_stats(context);
    let l7_stats = collect_l7_stats(context);
    let mut messages = vec![
        serialize_message("metrics", &metrics)?,
        serialize_message("l4_stats", &l4_stats)?,
        serialize_message("l7_stats", &l7_stats)?,
    ];
    if policy.include_traffic_map_in_fast_path {
        let traffic_map = collect_traffic_map(context).await;
        messages.push(serialize_message("traffic_map", &traffic_map)?);
    }

    Ok(messages)
}

async fn collect_periodic_messages(context: &WafContext) -> anyhow::Result<Vec<String>> {
    let recent_events = collect_recent_events(context).await?;
    let recent_blocked_ips = collect_recent_blocked_ips(context).await?;

    Ok(vec![
        serialize_message("recent_events", &recent_events)?,
        serialize_message("recent_blocked_ips", &recent_blocked_ips)?,
    ])
}

fn collect_metrics(
    context: &WafContext,
    storage_summary: Option<StorageMetricsSummary>,
) -> MetricsResponse {
    build_metrics_response(
        context.metrics_snapshot(),
        context.active_rule_count(),
        storage_summary,
        context
            .l4_inspector()
            .map(|inspector| inspector.get_statistics().behavior.overview),
        context.runtime_pressure_snapshot(),
    )
}

fn realtime_policy(context: &WafContext) -> RealtimePressurePolicy {
    let pressure = context.runtime_pressure_snapshot();
    match pressure.level {
        "attack" => RealtimePressurePolicy {
            fast_message_every_ticks: 5,
            periodic_message_every_ticks: 15,
            include_traffic_map_in_fast_path: false,
            security_event_sample_rate: 8,
            traffic_event_sample_rate: 12,
        },
        "high" => RealtimePressurePolicy {
            fast_message_every_ticks: 3,
            periodic_message_every_ticks: 10,
            include_traffic_map_in_fast_path: false,
            security_event_sample_rate: 4,
            traffic_event_sample_rate: 6,
        },
        "elevated" => RealtimePressurePolicy {
            fast_message_every_ticks: 2,
            periodic_message_every_ticks: 6,
            include_traffic_map_in_fast_path: true,
            security_event_sample_rate: 2,
            traffic_event_sample_rate: 3,
        },
        _ => RealtimePressurePolicy {
            fast_message_every_ticks: 1,
            periodic_message_every_ticks: 5,
            include_traffic_map_in_fast_path: true,
            security_event_sample_rate: 1,
            traffic_event_sample_rate: 1,
        },
    }
}

fn should_sample_out(sequence: u64, sample_rate: u64) -> bool {
    sample_rate > 1 && !sequence.is_multiple_of(sample_rate)
}

fn is_high_value_security_event(event: &crate::storage::SecurityEventEntry) -> bool {
    matches!(event.action.as_str(), "block" | "alert")
}

fn is_high_value_traffic_event(event: &crate::core::traffic_map::TrafficRealtimeEventRaw) -> bool {
    event.decision == "block"
        || (event.direction == "ingress" && event.bytes >= 64 * 1024)
        || event.latency_ms.unwrap_or(0) >= 1_000
}

async fn collect_storage_summary(context: &WafContext) -> Option<StorageMetricsSummary> {
    let Some(store) = context.sqlite_store.as_ref() else {
        return None;
    };

    match store.metrics_summary().await {
        Ok(summary) => Some(summary),
        Err(err) => {
            log::warn!(
                "Failed to query SQLite metrics summary for realtime feed: {}",
                err
            );
            None
        }
    }
}

fn collect_l4_stats(context: &WafContext) -> L4StatsResponse {
    context
        .l4_inspector()
        .as_ref()
        .map(|inspector| L4StatsResponse::from_stats(inspector.get_statistics()))
        .unwrap_or_else(L4StatsResponse::disabled)
}

fn collect_l7_stats(context: &WafContext) -> L7StatsResponse {
    L7StatsResponse::from_context(context)
}

async fn collect_recent_events(context: &WafContext) -> anyhow::Result<SecurityEventsResponse> {
    let Some(store) = context.sqlite_store.as_ref() else {
        return Ok(SecurityEventsResponse {
            total: 0,
            limit: 8,
            offset: 0,
            events: Vec::new(),
        });
    };

    let result = store
        .list_security_events(&SecurityEventQuery {
            limit: 8,
            offset: 0,
            layer: None,
            provider: None,
            provider_site_id: None,
            source_ip: None,
            action: None,
            identity_state: None,
            primary_signal: None,
            labels: Vec::new(),
            blocked_only: false,
            handled_only: None,
            created_from: None,
            created_to: None,
            sort_by: EventSortField::CreatedAt,
            sort_direction: SortDirection::Desc,
        })
        .await?;

    Ok(SecurityEventsResponse {
        total: result.total,
        limit: result.limit,
        offset: result.offset,
        events: result
            .items
            .into_iter()
            .map(SecurityEventResponse::from)
            .collect(),
    })
}

async fn collect_recent_blocked_ips(context: &WafContext) -> anyhow::Result<BlockedIpsResponse> {
    let Some(store) = context.sqlite_store.as_ref() else {
        return Ok(BlockedIpsResponse {
            total: 0,
            limit: 8,
            offset: 0,
            blocked_ips: Vec::new(),
        });
    };

    let result = store
        .list_blocked_ips(&BlockedIpQuery {
            limit: 8,
            offset: 0,
            source_scope: crate::storage::BlockedIpSourceScope::All,
            provider: None,
            ip: None,
            keyword: None,
            active_only: true,
            blocked_from: None,
            blocked_to: None,
            sort_by: BlockedIpSortField::BlockedAt,
            sort_direction: SortDirection::Desc,
        })
        .await?;

    Ok(BlockedIpsResponse {
        total: result.total,
        limit: result.limit,
        offset: result.offset,
        blocked_ips: result
            .items
            .into_iter()
            .map(BlockedIpResponse::from)
            .collect(),
    })
}

async fn collect_traffic_map(context: &WafContext) -> TrafficMapResponse {
    let snapshot = context.traffic_map_snapshot(60).await;
    let pressure = context.runtime_pressure_snapshot();

    TrafficMapResponse {
        scope: snapshot.scope,
        window_seconds: snapshot.window_seconds,
        generated_at: snapshot.generated_at,
        runtime_pressure_level: pressure.level.to_string(),
        degraded_reasons: Vec::new(),
        origin_node: TrafficMapNodeResponse {
            id: snapshot.origin_node.id,
            name: snapshot.origin_node.name,
            region: snapshot.origin_node.region,
            role: snapshot.origin_node.role,
            lat: snapshot.origin_node.lat,
            lng: snapshot.origin_node.lng,
            traffic_weight: snapshot.origin_node.traffic_weight,
            request_count: snapshot.origin_node.request_count,
            blocked_count: snapshot.origin_node.blocked_count,
            bandwidth_mbps: snapshot.origin_node.bandwidth_mbps,
            last_seen_at: snapshot.origin_node.last_seen_at,
        },
        nodes: snapshot
            .nodes
            .into_iter()
            .map(|item| TrafficMapNodeResponse {
                id: item.id,
                name: item.name,
                region: item.region,
                role: item.role,
                lat: item.lat,
                lng: item.lng,
                traffic_weight: item.traffic_weight,
                request_count: item.request_count,
                blocked_count: item.blocked_count,
                bandwidth_mbps: item.bandwidth_mbps,
                last_seen_at: item.last_seen_at,
            })
            .collect(),
        flows: snapshot
            .flows
            .into_iter()
            .map(|item| TrafficMapFlowResponse {
                id: item.id,
                node_id: item.node_id,
                direction: item.direction,
                decision: item.decision,
                request_count: item.request_count,
                bytes: item.bytes,
                bandwidth_mbps: item.bandwidth_mbps,
                average_latency_ms: item.average_latency_ms,
                last_seen_at: item.last_seen_at,
            })
            .collect(),
        active_node_count: snapshot.active_node_count,
        peak_bandwidth_mbps: snapshot.peak_bandwidth_mbps,
        allowed_flow_count: snapshot.allowed_flow_count,
        blocked_flow_count: snapshot.blocked_flow_count,
        live_traffic_score: snapshot.live_traffic_score,
    }
}

fn serialize_message<T: Serialize>(topic: &'static str, payload: &T) -> anyhow::Result<String> {
    Ok(serde_json::to_string(&RealtimeEnvelope {
        topic,
        payload: serde_json::to_value(payload)?,
    })?)
}

fn random_ticket() -> String {
    use rand::{distributions::Alphanumeric, Rng};

    rand::thread_rng()
        .sample_iter(Alphanumeric)
        .take(48)
        .map(char::from)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sample_rate_one_keeps_everything() {
        assert!(!should_sample_out(1, 1));
        assert!(!should_sample_out(2, 1));
    }

    #[test]
    fn sample_rate_n_keeps_only_stride() {
        assert!(should_sample_out(1, 4));
        assert!(should_sample_out(2, 4));
        assert!(should_sample_out(3, 4));
        assert!(!should_sample_out(4, 4));
    }

    #[test]
    fn high_value_traffic_event_bypasses_sampling() {
        let blocked = crate::core::traffic_map::TrafficRealtimeEventRaw {
            timestamp_ms: 1,
            source_ip: "203.0.113.10".to_string(),
            direction: "ingress".to_string(),
            decision: "block".to_string(),
            bytes: 128,
            latency_ms: None,
        };
        assert!(is_high_value_traffic_event(&blocked));
    }
}

fn unix_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
