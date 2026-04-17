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
    Drop,
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
    pub failure_statuses: Vec<u16>,
    pub success_rate_percent: u8,
    pub success_body: Vec<u8>,
    pub failure_body: Vec<u8>,
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

    pub fn respond_and_persist_ip(
        layer: InspectionLayer,
        reason: impl Into<String>,
        custom_response: CustomHttpResponse,
    ) -> Self {
        Self {
            persist_blocked_ip: true,
            ..Self::respond(layer, reason, custom_response)
        }
    }

    pub fn block_and_persist_ip(layer: InspectionLayer, reason: impl Into<String>) -> Self {
        Self {
            persist_blocked_ip: true,
            ..Self::block(layer, reason)
        }
    }

    pub fn drop(layer: InspectionLayer, reason: impl Into<String>) -> Self {
        Self {
            blocked: true,
            reason: reason.into(),
            layer,
            action: InspectionAction::Drop,
            persist_blocked_ip: false,
            custom_response: None,
        }
    }

    pub fn drop_and_persist_ip(layer: InspectionLayer, reason: impl Into<String>) -> Self {
        Self {
            persist_blocked_ip: true,
            ..Self::drop(layer, reason)
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
            InspectionAction::Drop => "drop",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inspection_actions_report_event_and_persistence_contract() {
        let allow = InspectionResult::allow(InspectionLayer::L4);
        assert!(!allow.blocked);
        assert_eq!(allow.event_action(), "allow");
        assert!(!allow.should_persist_event());

        let alert = InspectionResult::alert(InspectionLayer::L7, "watch");
        assert!(!alert.blocked);
        assert_eq!(alert.event_action(), "alert");
        assert!(alert.should_persist_event());

        let block = InspectionResult::block(InspectionLayer::L4, "block");
        assert!(block.blocked);
        assert_eq!(block.event_action(), "block");
        assert!(!block.persist_blocked_ip);
        assert!(block.should_persist_event());

        let block_and_persist =
            InspectionResult::block_and_persist_ip(InspectionLayer::L4, "block ip");
        assert!(block_and_persist.blocked);
        assert_eq!(block_and_persist.event_action(), "block");
        assert!(block_and_persist.persist_blocked_ip);

        let response = CustomHttpResponse {
            status_code: 403,
            headers: Vec::new(),
            body: b"blocked".to_vec(),
            tarpit: None,
            random_status: None,
        };
        let respond = InspectionResult::respond(InspectionLayer::L7, "respond", response);
        assert!(respond.blocked);
        assert_eq!(respond.event_action(), "respond");
        assert!(respond.custom_response.is_some());
        assert!(respond.should_persist_event());

        let drop = InspectionResult::drop(InspectionLayer::L7, "drop");
        assert!(drop.blocked);
        assert_eq!(drop.event_action(), "drop");
        assert!(drop.custom_response.is_none());
        assert!(!drop.persist_blocked_ip);
        assert!(drop.should_persist_event());

        let drop_and_persist =
            InspectionResult::drop_and_persist_ip(InspectionLayer::L7, "drop ip");
        assert!(drop_and_persist.blocked);
        assert_eq!(drop_and_persist.event_action(), "drop");
        assert!(drop_and_persist.custom_response.is_none());
        assert!(drop_and_persist.persist_blocked_ip);
    }
}
