use crate::config::Http3Config;
use crate::protocol::{HttpVersion, ProtocolError, UnifiedHttpRequest};
use http::Request;
use log::{debug, warn};
use std::collections::HashMap;
use std::net::SocketAddr;

/// HTTP/3.0处理器
///
/// 当前实现聚焦在 QUIC datagram 识别与元数据提取。
/// 未启用 TLS 终止时，WAF 无法解密 HTTP/3 头部和请求体，因此这里不会伪造明文请求。
pub struct Http3Handler {
    config: Http3Config,
    pub max_concurrent_streams: usize,
    enable_quic_metrics: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuicPacketInfo {
    pub header_form: &'static str,
    pub packet_type: String,
    pub version: Option<u32>,
    pub version_label: String,
    pub destination_connection_id: Option<String>,
    pub source_connection_id: Option<String>,
    pub payload_len: usize,
}

impl Http3Handler {
    /// 创建新的HTTP/3.0处理器
    pub fn new(config: Http3Config) -> Self {
        Self {
            max_concurrent_streams: config.max_concurrent_streams,
            config,
            enable_quic_metrics: false,
        }
    }

    /// 设置最大并发流数
    #[allow(dead_code)]
    pub fn with_max_concurrent_streams(mut self, max: usize) -> Self {
        self.max_concurrent_streams = max;
        self
    }

    /// 启用/禁用QUIC指标
    #[allow(dead_code)]
    pub fn with_quic_metrics(mut self, enabled: bool) -> Self {
        self.enable_quic_metrics = enabled;
        self
    }

    /// 判断一个 UDP datagram 是否像 QUIC / HTTP/3 流量。
    pub fn is_quic_datagram(&self, payload: &[u8]) -> bool {
        if payload.len() < 2 {
            return false;
        }

        let first = payload[0];
        let has_fixed_bit = (first & 0x40) != 0;
        if !has_fixed_bit {
            return false;
        }

        if self.is_long_header(payload) {
            payload.len() >= 7
        } else {
            payload.len() >= 2
        }
    }

    /// 解析 QUIC datagram 并转成统一检测上下文。
    pub fn inspect_datagram(
        &self,
        payload: &[u8],
        peer_addr: SocketAddr,
        local_addr: SocketAddr,
    ) -> Result<Option<UnifiedHttpRequest>, ProtocolError> {
        if !self.config.enabled {
            return Ok(None);
        }

        let packet_info = match self.parse_quic_packet(payload)? {
            Some(packet_info) => packet_info,
            None => return Ok(None),
        };

        let mut request = UnifiedHttpRequest::new(
            HttpVersion::Http3_0,
            "QUIC".to_string(),
            format!("/quic/{}", packet_info.packet_type),
        );

        request.set_client_ip(peer_addr.ip().to_string());
        request.add_header("content-type".to_string(), "application/quic".to_string());
        request.add_metadata("listener_port".to_string(), local_addr.port().to_string());
        request.add_metadata("protocol".to_string(), "HTTP/3.0".to_string());
        request.add_metadata("transport".to_string(), "quic".to_string());
        request.add_metadata(
            "quic.header_form".to_string(),
            packet_info.header_form.to_string(),
        );
        request.add_metadata("quic.packet_type".to_string(), packet_info.packet_type.clone());
        request.add_metadata(
            "quic.version".to_string(),
            packet_info.version_label.clone(),
        );
        request.add_metadata(
            "quic.payload_len".to_string(),
            packet_info.payload_len.to_string(),
        );
        request.add_metadata("udp.peer".to_string(), peer_addr.to_string());
        request.add_metadata("udp.local".to_string(), local_addr.to_string());

        if let Some(version) = packet_info.version {
            request.add_metadata("quic.version_raw".to_string(), format!("0x{version:08x}"));
        }

        if let Some(dcid) = packet_info.destination_connection_id {
            request.add_metadata("quic.dcid".to_string(), dcid);
        }

        if let Some(scid) = packet_info.source_connection_id {
            request.add_metadata("quic.scid".to_string(), scid);
        }

        if self.enable_quic_metrics {
            debug!("QUIC packet metadata: {:?}", request.metadata);
        }

        Ok(Some(request))
    }

    pub fn parse_quic_packet(
        &self,
        payload: &[u8],
    ) -> Result<Option<QuicPacketInfo>, ProtocolError> {
        if !self.is_quic_datagram(payload) {
            return Ok(None);
        }

        let first = payload[0];
        if self.is_long_header(payload) {
            parse_long_header_packet(first, payload).map(Some)
        } else {
            Ok(Some(QuicPacketInfo {
                header_form: "short",
                packet_type: "short".to_string(),
                version: None,
                version_label: "unknown".to_string(),
                destination_connection_id: None,
                source_connection_id: None,
                payload_len: payload.len(),
            }))
        }
    }

    fn is_long_header(&self, payload: &[u8]) -> bool {
        payload.first().map(|first| (first & 0x80) != 0).unwrap_or(false)
    }

    pub fn request_to_unified(
        &self,
        request: &Request<()>,
        body: Vec<u8>,
        client_ip: &str,
        listener_port: u16,
    ) -> UnifiedHttpRequest {
        let method = request.method().as_str().to_string();
        let uri = request
            .uri()
            .path_and_query()
            .map(|pq| pq.as_str().to_string())
            .unwrap_or_else(|| request.uri().path().to_string());

        let mut unified = UnifiedHttpRequest::new(HttpVersion::Http3_0, method, uri);
        unified.body = body;
        unified.set_client_ip(client_ip.to_string());
        unified.add_metadata("listener_port".to_string(), listener_port.to_string());
        unified.add_metadata("protocol".to_string(), "HTTP/3.0".to_string());
        unified.add_metadata("transport".to_string(), "quic".to_string());

        if let Some(scheme) = request.uri().scheme_str() {
            unified.add_metadata("scheme".to_string(), scheme.to_string());
        }

        let authority = request
            .uri()
            .authority()
            .map(|authority| authority.as_str().to_string())
            .or_else(|| {
                request
                    .headers()
                    .get("host")
                    .and_then(|host| host.to_str().ok())
                    .map(|host| host.to_string())
            });

        if let Some(authority) = authority {
            unified.add_metadata("authority".to_string(), authority.clone());
            if unified.get_header("host").is_none() {
                unified.add_header("host".to_string(), authority);
            }
        }

        for (key, value) in request.headers() {
            if let Ok(value) = value.to_str() {
                unified.add_header(key.as_str().to_string(), value.to_string());
            }
        }

        unified
    }
}

/// HTTP/3.0流管理器
///
/// 管理HTTP/3.0中的QUIC流，包括创建、销毁、优先级处理等
#[allow(dead_code)]
pub struct Http3StreamManager {
    active_streams: HashMap<u64, StreamState>,
    next_stream_id: u64,
    pub max_concurrent_streams: usize,
    pub enable_priorities: bool,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
struct StreamState {
    window_size: u32,
    bytes_sent: u64,
    bytes_received: u64,
    priority: u8,
}

#[allow(dead_code)]
impl Http3StreamManager {
    /// 创建新的HTTP/3.0流管理器
    pub fn new(max_concurrent_streams: usize, enable_priorities: bool) -> Self {
        Self {
            active_streams: HashMap::new(),
            next_stream_id: 1,
            max_concurrent_streams,
            enable_priorities,
        }
    }

    /// 创建新的流
    pub fn create_stream(&mut self) -> Option<u64> {
        if self.active_streams.len() >= self.max_concurrent_streams {
            warn!("Maximum concurrent streams reached");
            return None;
        }

        let stream_id = self.next_stream_id;
        self.next_stream_id += 4;

        let state = StreamState {
            window_size: 65_535,
            bytes_sent: 0,
            bytes_received: 0,
            priority: 128,
        };

        self.active_streams.insert(stream_id, state);
        debug!("Created HTTP/3.0 stream: {}", stream_id);
        Some(stream_id)
    }

    /// 关闭流
    pub fn close_stream(&mut self, stream_id: u64) {
        if self.active_streams.remove(&stream_id).is_some() {
            debug!("Closed HTTP/3.0 stream: {}", stream_id);
        }
    }

    /// 更新流窗口大小
    pub fn update_window(&mut self, stream_id: u64, increment: u32) {
        if let Some(state) = self.active_streams.get_mut(&stream_id) {
            state.window_size = state.window_size.saturating_add(increment);
            debug!(
                "Updated window for stream {}: {}",
                stream_id, state.window_size
            );
        }
    }

    /// 获取活动流数量
    pub fn active_stream_count(&self) -> usize {
        self.active_streams.len()
    }

    /// 检查流是否存在
    pub fn stream_exists(&self, stream_id: u64) -> bool {
        self.active_streams.contains_key(&stream_id)
    }

    /// 设置流优先级
    pub fn set_priority(&mut self, stream_id: u64, priority: u8) {
        if let Some(state) = self.active_streams.get_mut(&stream_id) {
            if self.enable_priorities {
                state.priority = priority;
                debug!("Set priority {} for stream {}", priority, stream_id);
            }
        }
    }

    /// 获取流统计信息
    pub fn get_stream_stats(&self, stream_id: u64) -> Option<(u64, u64, u32, u8)> {
        self.active_streams.get(&stream_id).map(|state| {
            (
                state.bytes_sent,
                state.bytes_received,
                state.window_size,
                state.priority,
            )
        })
    }
}

fn parse_long_header_packet(
    first: u8,
    payload: &[u8],
) -> Result<QuicPacketInfo, ProtocolError> {
    if payload.len() < 6 {
        return Err(ProtocolError::ParseError(
            "QUIC long header too short".to_string(),
        ));
    }

    let version = u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);
    let mut offset = 5usize;
    let dcid_len = *payload.get(offset).ok_or_else(|| {
        ProtocolError::ParseError("Missing QUIC destination connection id length".to_string())
    })? as usize;
    offset += 1;

    let dcid_end = offset + dcid_len;
    if payload.len() < dcid_end {
        return Err(ProtocolError::ParseError(
            "Truncated QUIC destination connection id".to_string(),
        ));
    }
    let dcid = hex_bytes(&payload[offset..dcid_end]);
    offset = dcid_end;

    let scid_len = *payload.get(offset).ok_or_else(|| {
        ProtocolError::ParseError("Missing QUIC source connection id length".to_string())
    })? as usize;
    offset += 1;

    let scid_end = offset + scid_len;
    if payload.len() < scid_end {
        return Err(ProtocolError::ParseError(
            "Truncated QUIC source connection id".to_string(),
        ));
    }
    let scid = hex_bytes(&payload[offset..scid_end]);

    let packet_type = if version == 0 {
        "version_negotiation".to_string()
    } else {
        match (first & 0x30) >> 4 {
            0 => "initial".to_string(),
            1 => "0rtt".to_string(),
            2 => "handshake".to_string(),
            3 => "retry".to_string(),
            _ => "unknown".to_string(),
        }
    };

    Ok(QuicPacketInfo {
        header_form: "long",
        packet_type,
        version: Some(version),
        version_label: quic_version_label(version),
        destination_connection_id: (!dcid.is_empty()).then_some(dcid),
        source_connection_id: (!scid.is_empty()).then_some(scid),
        payload_len: payload.len(),
    })
}

fn quic_version_label(version: u32) -> String {
    match version {
        0x0000_0000 => "version_negotiation".to_string(),
        0x0000_0001 => "rfc9000".to_string(),
        0x6b33_43cf => "quic_v2".to_string(),
        0xff00_001d => "draft-29".to_string(),
        other => format!("0x{other:08x}"),
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http3_handler_creation() {
        let config = Http3Config::default();
        let handler = Http3Handler::new(config);

        assert_eq!(handler.max_concurrent_streams, 100);
    }

    #[test]
    fn test_http3_handler_with_options() {
        let config = Http3Config::default();
        let handler = Http3Handler::new(config)
            .with_max_concurrent_streams(50)
            .with_quic_metrics(true);

        assert_eq!(handler.max_concurrent_streams, 50);
        assert!(handler.enable_quic_metrics);
    }

    #[test]
    fn test_parse_quic_initial_packet() {
        let handler = Http3Handler::new(Http3Config {
            enabled: true,
            ..Http3Config::default()
        });
        let payload = [
            0xc0, 0x00, 0x00, 0x00, 0x01, 0x08, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe,
            0xef, 0x04, 0xca, 0xfe, 0xba, 0xbe, 0x00, 0x01,
        ];

        let packet = handler.parse_quic_packet(&payload).unwrap().unwrap();
        assert_eq!(packet.header_form, "long");
        assert_eq!(packet.packet_type, "initial");
        assert_eq!(packet.version, Some(1));
        assert_eq!(packet.version_label, "rfc9000");
        assert_eq!(
            packet.destination_connection_id,
            Some("deadbeefdeadbeef".to_string())
        );
        assert_eq!(packet.source_connection_id, Some("cafebabe".to_string()));
    }

    #[test]
    fn test_non_quic_datagram_is_ignored() {
        let handler = Http3Handler::new(Http3Config {
            enabled: true,
            ..Http3Config::default()
        });
        let payload = [0x10, 0x20, 0x30, 0x40];

        assert!(!handler.is_quic_datagram(&payload));
        assert!(handler.parse_quic_packet(&payload).unwrap().is_none());
    }

    #[test]
    fn test_short_header_quic_packet() {
        let handler = Http3Handler::new(Http3Config {
            enabled: true,
            ..Http3Config::default()
        });
        let payload = [0x41, 0x12, 0x34, 0x56];

        let packet = handler.parse_quic_packet(&payload).unwrap().unwrap();
        assert_eq!(packet.header_form, "short");
        assert_eq!(packet.packet_type, "short");
    }

    #[test]
    fn test_http3_stream_manager() {
        let mut manager = Http3StreamManager::new(10, true);

        let stream_id = manager.create_stream();
        assert!(stream_id.is_some());
        assert_eq!(stream_id.unwrap(), 1);
        assert_eq!(manager.active_stream_count(), 1);

        manager.set_priority(1, 200);
        let stats = manager.get_stream_stats(1).unwrap();
        assert_eq!(stats.3, 200);
    }

    #[test]
    fn test_http3_request_to_unified() {
        let handler = Http3Handler::new(Http3Config::default());
        let request = Request::builder()
            .method("POST")
            .uri("https://example.com/upload?id=1")
            .header("content-type", "application/octet-stream")
            .body(())
            .unwrap();

        let unified = handler.request_to_unified(&request, b"hello".to_vec(), "127.0.0.1", 8443);
        assert_eq!(unified.version, HttpVersion::Http3_0);
        assert_eq!(unified.uri, "/upload?id=1");
        assert_eq!(
            unified.get_metadata("authority"),
            Some(&"example.com".to_string())
        );
        assert_eq!(unified.body, b"hello".to_vec());
    }
}
