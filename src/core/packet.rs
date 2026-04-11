use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketInfo {
    pub source_ip: IpAddr,
    pub dest_ip: IpAddr,
    pub source_port: u16,
    pub dest_port: u16,
    pub protocol: Protocol,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Protocol {
    TCP,
    UDP,
    ICMP,
    Other(u8),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InspectionResult {
    pub blocked: bool,
    pub reason: String,
    pub layer: InspectionLayer,
    pub action: InspectionAction,
    pub persist_blocked_ip: bool,
    pub custom_response: Option<CustomHttpResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum InspectionLayer {
    L4,
    L7,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum InspectionAction {
    Allow,
    Block,
    Alert,
    Respond,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomHttpResponse {
    pub status_code: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub tarpit: Option<TarpitConfig>,
    pub random_status: Option<RandomStatusConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TarpitConfig {
    pub bytes_per_chunk: usize,
    pub chunk_interval_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RandomStatusConfig {
    pub statuses: Vec<u16>,
}

impl PacketInfo {
    pub fn from_socket_addrs(source: SocketAddr, dest: SocketAddr, protocol: Protocol) -> Self {
        Self {
            source_ip: source.ip(),
            dest_ip: dest.ip(),
            source_port: source.port(),
            dest_port: dest.port(),
            protocol,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }
}

impl InspectionResult {
    pub fn allow(layer: InspectionLayer) -> Self {
        Self {
            blocked: false,
            reason: String::new(),
            layer,
            action: InspectionAction::Allow,
            persist_blocked_ip: false,
            custom_response: None,
        }
    }

    pub fn allow_with_reason(layer: InspectionLayer, reason: impl Into<String>) -> Self {
        Self {
            blocked: false,
            reason: reason.into(),
            layer,
            action: InspectionAction::Allow,
            persist_blocked_ip: false,
            custom_response: None,
        }
    }

    pub fn alert(layer: InspectionLayer, reason: impl Into<String>) -> Self {
        Self {
            blocked: false,
            reason: reason.into(),
            layer,
            action: InspectionAction::Alert,
            persist_blocked_ip: false,
            custom_response: None,
        }
    }

    pub fn block(layer: InspectionLayer, reason: impl Into<String>) -> Self {
        Self {
            blocked: true,
            reason: reason.into(),
            layer,
            action: InspectionAction::Block,
            persist_blocked_ip: false,
            custom_response: None,
        }
    }

    pub fn respond(
        layer: InspectionLayer,
        reason: impl Into<String>,
        custom_response: CustomHttpResponse,
    ) -> Self {
        Self {
            blocked: true,
            reason: reason.into(),
            layer,
            action: InspectionAction::Respond,
            persist_blocked_ip: false,
            custom_response: Some(custom_response),
        }
    }

    pub fn block_and_persist_ip(layer: InspectionLayer, reason: impl Into<String>) -> Self {
        Self {
            persist_blocked_ip: true,
            ..Self::block(layer, reason)
        }
    }

    pub fn should_persist_event(&self) -> bool {
        self.blocked
            || matches!(
                self.action,
                InspectionAction::Alert | InspectionAction::Respond
            )
    }

    pub fn event_action(&self) -> &'static str {
        match self.action {
            InspectionAction::Allow => "allow",
            InspectionAction::Block => "block",
            InspectionAction::Alert => "alert",
            InspectionAction::Respond => "respond",
        }
    }
}
