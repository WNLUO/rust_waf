use super::metrics::build_metrics_response;
use super::state::ApiState;
use super::types::{
    BlockedIpResponse, BlockedIpsResponse, L4StatsResponse, L7StatsResponse, MetricsResponse,
    SecurityEventResponse, SecurityEventsResponse, TrafficMapFlowResponse, TrafficMapNodeResponse,
    TrafficMapResponse,
};
use crate::core::WafContext;
use crate::storage::{
    BlockedIpQuery, BlockedIpSortField, EventSortField, SecurityEventQuery, SortDirection,
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

        loop {
            interval.tick().await;
            if let Ok(messages) = collect_messages(context.as_ref()).await {
                for message in messages {
                    let _ = realtime_tx.send(message);
                }
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
    let metrics = collect_metrics(context).await;
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

async fn collect_metrics(context: &WafContext) -> MetricsResponse {
    let storage_summary = if let Some(store) = context.sqlite_store.as_ref() {
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
    } else {
        None
    };

    build_metrics_response(
        context.metrics_snapshot(),
        context.active_rule_count(),
        storage_summary,
        context
            .l4_inspector()
            .map(|inspector| inspector.get_statistics().behavior.overview),
    )
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

    TrafficMapResponse {
        scope: snapshot.scope,
        window_seconds: snapshot.window_seconds,
        generated_at: snapshot.generated_at,
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

fn unix_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
