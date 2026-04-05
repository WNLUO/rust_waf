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
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum InspectionLayer {
    L4,
    L7,
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
        }
    }
}
