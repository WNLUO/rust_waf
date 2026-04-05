use crate::protocol::{HttpVersion, UnifiedHttpRequest, ProtocolError};
use crate::config::Http3Config;
use log::{debug, info, warn};
use anyhow::Result;

// HTTP/3.0处理器
///
/// 处理基于QUIC协议的HTTP/3.0请求和响应，支持多路复用和连接迁移
pub struct Http3Handler {
    config: Http3Config,
    pub max_concurrent_streams: usize,
    #[allow(dead_code)]
    _enable_quic_metrics: bool, // 以下划线避免警告
}

impl Http3Handler {
    /// 创建新的HTTP/3.0处理器
    pub fn new(config: Http3Config) -> Self {
        info!("Initializing HTTP/3.0 handler");

        if config.enabled {
            info!("HTTP/3.0 support enabled on {}", config.listen_addr);
            info!("Max concurrent streams: {}", config.max_concurrent_streams);
            info!("MTU: {}", config.mtu);
            info!("QPACK table size: {}", config.qpack_table_size);
        } else {
            debug!("HTTP/3.0 support disabled");
        }

        Self {
            config: config.clone(),
            max_concurrent_streams: config.max_concurrent_streams,
            _enable_quic_metrics: false, // Default value since config doesn't have this field
        }
    }

    /// 设置最大并发流数
    pub fn with_max_concurrent_streams(mut self, max: usize) -> Self {
        self.max_concurrent_streams = max;
        self
    }

    /// 启用/禁用QUIC指标
    pub fn with_quic_metrics(mut self, enabled: bool) -> Self {
        self._enable_quic_metrics = enabled;
        self
    }

    /// 读取HTTP/3.0请求
    ///
    /// 在实际的QUIC + h3实现中，这里会：
    /// - 建立QUIC连接
    /// - 读取HTTP/3.0流
    /// - 使用h3库解析HTTP/3.0帧
    /// - 处理QPACK头部解压缩
    /// - 转换为UnifiedHttpRequest结构
    ///
    /// 当前实现使用模拟的连接和流
    pub async fn read_request<R>(&self, _conn: &mut R, _max_size: usize) -> Result<UnifiedHttpRequest, ProtocolError>
    where
        R: std::marker::Send + std::marker::Sync,
    {
        if !self.config.enabled {
            return Err(ProtocolError::ParseError(
                "HTTP/3.0 support is not enabled".to_string()
            ));
        }

        debug!("Reading HTTP/3.0 request");

        // 模拟HTTP/3.0请求解析
        let mut request = UnifiedHttpRequest::new(
            HttpVersion::Http3_0,
            "GET".to_string(),
            "/".to_string()
        );

        // 添加HTTP/3.0特定的伪头部（实际QPACK压缩的头部）
        request.add_header(":method".to_string(), "GET".to_string());
        request.add_header(":path".to_string(), "/".to_string());
        request.add_header(":scheme".to_string(), "https".to_string());

        // 添加常见的HTTP头
        request.add_header("User-Agent".to_string(), "HTTP/3.0 Test Client".to_string());
        request.add_header("Accept".to_string(), "*/*".to_string());
        request.add_header("Content-Type".to_string(), "application/json".to_string());

        info!("Parsed HTTP/3.0 request: {} {}", request.method, request.uri);
        Ok(request)
    }

    /// 写入HTTP/3.0响应
    ///
    /// 在实际的QUIC + h3实现中，这里会：
    /// - 使用h3库构建HTTP/3.0帧
    /// - 使用QPACK压缩头部
    /// - 通过QUIC流发送数据
    pub async fn write_response<W>(
        &self,
        _stream: &mut W,
        _stream_id: u64,
        status_code: u16,
        _headers: &[(String, String)],
        body: &[u8],
    ) -> Result<(), ProtocolError>
    where
        W: std::marker::Send + std::marker::Sync,
    {
        if !self.config.enabled {
            return Err(ProtocolError::ParseError(
                "HTTP/3.0 support is not enabled".to_string()
            ));
        }

        debug!("Writing HTTP/3.0 response for stream {}: status {}, body size {}",
                _stream_id, status_code, body.len());

        // 模拟HTTP/3.0响应写入
        // 在实际实现中会使用h3库发送HTTP/3.0响应
        Ok(())
    }
}

/// HTTP/3.0流管理器
///
/// 管理HTTP/3.0中的QUIC流，包括创建、销毁、优先级处理等
pub struct Http3StreamManager {
    active_streams: std::collections::HashMap<u64, StreamState>,
    next_stream_id: u64,
    pub max_concurrent_streams: usize,
    pub enable_priorities: bool,
}

#[derive(Debug, Clone)]
struct StreamState {
    stream_id: u64,
    state: StreamStateType,
    window_size: u32,
    bytes_sent: u64,
    bytes_received: u64,
    priority: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StreamStateType {
    Idle,
    Open,
    HalfClosedRemote,
    HalfClosedLocal,
    Closed,
}

impl Http3StreamManager {
    /// 创建新的HTTP/3.0流管理器
    pub fn new(max_concurrent_streams: usize, enable_priorities: bool) -> Self {
        info!("Creating HTTP/3.0 stream manager");
        Self {
            active_streams: std::collections::HashMap::new(),
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
        self.next_stream_id += 4; // 客户端发起的流ID为奇数

        let state = StreamState {
            stream_id,
            state: StreamStateType::Idle,
            window_size: 65535, // HTTP/3.0默认窗口大小
            bytes_sent: 0,
            bytes_received: 0,
            priority: 128, // 默认中等优先级
        };

        self.active_streams.insert(stream_id, state);
        debug!("Created HTTP/3.0 stream: {}", stream_id);
        Some(stream_id)
    }

    /// 关闭流
    pub fn close_stream(&mut self, stream_id: u64) {
        if let Some(_state) = self.active_streams.remove(&stream_id) {
            debug!("Closed HTTP/3.0 stream: {}", stream_id);
        }
    }

    /// 更新流窗口大小
    pub fn update_window(&mut self, stream_id: u64, increment: u32) {
        if let Some(state) = self.active_streams.get_mut(&stream_id) {
            state.window_size = state.window_size.saturating_add(increment);
            debug!("Updated window for stream {}: {}", stream_id, state.window_size);
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
            (state.bytes_sent, state.bytes_received, state.window_size, state.priority)
        })
    }
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
            .with_quic_metrics(false);

        assert_eq!(handler.max_concurrent_streams, 50);
        assert!(!handler._enable_quic_metrics);
    }

    #[test]
    fn test_stream_manager_creation() {
        let manager = Http3StreamManager::new(10, true);

        assert_eq!(manager.active_stream_count(), 0);
        assert_eq!(manager.max_concurrent_streams, 10);
        assert!(manager.enable_priorities);
    }

    #[test]
    fn test_stream_manager_basic_operations() {
        let mut manager = Http3StreamManager::new(10, true);

        // 测试流创建
        let stream_id1 = manager.create_stream().unwrap();
        let stream_id2 = manager.create_stream().unwrap();

        assert_eq!(stream_id1, 1);
        assert_eq!(stream_id2, 5);
        assert_eq!(manager.active_stream_count(), 2);

        // 测试流关闭
        manager.close_stream(1);
        assert_eq!(manager.active_stream_count(), 1);
        assert!(!manager.stream_exists(1));

        // 测试流限制
        for _ in 0..8 {
            manager.create_stream();
        }
        let over_limit = manager.create_stream();
        assert!(over_limit.is_some()); // Should succeed (1 + 8 + 1 = 10)
        assert_eq!(manager.active_stream_count(), 10);

        // Test exceeding the limit
        let exceed_limit = manager.create_stream();
        assert!(exceed_limit.is_none()); // Should fail (10 + 1 = 11 > 10)
        assert_eq!(manager.active_stream_count(), 10);
    }

    #[test]
    fn test_stream_manager_priorities() {
        let mut manager = Http3StreamManager::new(10, true);

        let stream_id = manager.create_stream().unwrap();
        manager.set_priority(stream_id, 255);

        let stats = manager.get_stream_stats(stream_id).unwrap();
        assert_eq!(stats.3, 255); // 高优先级
    }

    #[test]
    fn test_stream_manager_window_update() {
        let mut manager = Http3StreamManager::new(10, false);

        let stream_id = manager.create_stream().unwrap();
        manager.update_window(stream_id, 1000);

        let stats = manager.get_stream_stats(stream_id).unwrap();
        assert_eq!(stats.2, 65535 + 1000); // 默认窗口大小+增量
    }
}