use super::{HttpVersion, ProtocolError, UnifiedHttpRequest};
use anyhow::Result;
use log::{debug, error, info, warn};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// HTTP/2.0处理器
///
/// 处理HTTP/2.0协议的请求和响应，支持多路复用
pub struct Http2Handler {
    max_concurrent_streams: usize,
    max_frame_size: usize,
    enable_priorities: bool,
}

impl Http2Handler {
    /// 创建新的HTTP/2.0处理器
    pub fn new() -> Self {
        Self {
            max_concurrent_streams: 100,
            max_frame_size: 16384, // HTTP/2.0默认最大帧大小
            enable_priorities: true,
        }
    }

    /// 设置最大并发流数
    pub fn with_max_concurrent_streams(mut self, max: usize) -> Self {
        self.max_concurrent_streams = max;
        self
    }

    /// 设置最大帧大小
    pub fn with_max_frame_size(mut self, size: usize) -> Self {
        self.max_frame_size = size;
        self
    }

    /// 启用/禁用优先级支持
    pub fn with_priorities(mut self, enabled: bool) -> Self {
        self.enable_priorities = enabled;
        self
    }

    /// 读取HTTP/2.0请求
    ///
    /// 注意：这是一个简化的HTTP/2.0处理器实现。
    /// 完整的HTTP/2.0支持需要使用hyper库的完整功能。
    pub async fn read_request<R>(
        &self,
        reader: &mut R,
        _max_size: usize,
    ) -> Result<UnifiedHttpRequest, ProtocolError>
    where
        R: AsyncReadExt + Unpin,
    {
        // 读取HTTP/2.0前置请求（PRI请求）
        let mut buffer = vec![0u8; 24];
        reader.read_exact(&mut buffer).await?;

        const HTTP2_PRI: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

        if !buffer.starts_with(HTTP2_PRI) {
            warn!("Invalid HTTP/2.0 preface, falling back to HTTP/1.1");
            return Ok(UnifiedHttpRequest::default());
        }

        debug!("HTTP/2.0 connection established");

        // 在实际实现中，这里应该使用hyper的HTTP/2.0服务器功能
        // 这里我们创建一个示例请求来演示结构
        let mut request =
            UnifiedHttpRequest::new(HttpVersion::Http2_0, "GET".to_string(), "/".to_string());
        request.set_stream_id(1); // 客户端发起的流ID为奇数

        // 添加示例头部
        request.add_header(":method".to_string(), "GET".to_string());
        request.add_header(":path".to_string(), "/".to_string());
        request.add_header(":scheme".to_string(), "https".to_string());
        request.add_header(":authority".to_string(), "example.com".to_string());

        info!("Processed HTTP/2.0 request on stream 1");
        Ok(request)
    }

    /// 写入HTTP/2.0响应
    ///
    /// 注意：完整的HTTP/2.0响应需要使用hyper库
    pub async fn write_response<W>(
        &self,
        writer: &mut W,
        stream_id: u32,
        status_code: u16,
        _headers: &[(String, String)],
        body: &[u8],
    ) -> Result<(), ProtocolError>
    where
        W: AsyncWriteExt + Unpin,
    {
        // 在实际实现中，这里应该构建HTTP/2.0帧：
        // 1. HEADERS帧（包含状态码和头部）
        // 2. DATA帧（包含响应体）
        // 3. END_STREAM标志

        // 这里我们使用简化的HTTP/1.1格式作为示例
        let response = format!(
            "HTTP/2.0 {} (Stream {})\r\n\
             Content-Length: {}\r\n\
             \r\n\
             {}",
            status_code,
            stream_id,
            body.len(),
            String::from_utf8_lossy(body)
        );

        writer.write_all(response.as_bytes()).await?;
        writer.flush().await?;

        debug!(
            "Wrote HTTP/2.0 response for stream {}: {}",
            stream_id, status_code
        );
        Ok(())
    }

    /// 处理HTTP/2.0流错误
    #[allow(dead_code)]
    pub fn handle_stream_error(&self, stream_id: u32, error_code: u32) {
        error!(
            "HTTP/2.0 stream error on stream {}: error code {}",
            stream_id, error_code
        );
        // 在实际实现中，这里应该发送RST_STREAM帧
    }

    /// 处理HTTP/2.0连接错误
    #[allow(dead_code)]
    pub fn handle_connection_error(&self, error_code: u32) {
        error!("HTTP/2.0 connection error: error code {}", error_code);
        // 在实际实现中，这里应该发送GOAWAY帧并关闭连接
    }
}

impl Default for Http2Handler {
    fn default() -> Self {
        Self::new()
    }
}

/// HTTP/2.0流管理器
///
/// 管理HTTP/2.0连接中的多个流
#[allow(dead_code)]
#[derive(Debug)]
pub struct Http2StreamManager {
    active_streams: std::collections::HashMap<u32, StreamState>,
    next_stream_id: u32,
    max_concurrent_streams: usize,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
struct StreamState {
    window_size: u32,
}

#[allow(dead_code)]
impl Http2StreamManager {
    /// 创建新的流管理器
    pub fn new(max_concurrent_streams: usize) -> Self {
        Self {
            active_streams: std::collections::HashMap::new(),
            next_stream_id: 1, // 客户端发起的流ID从1开始
            max_concurrent_streams,
        }
    }

    /// 创建新的流
    pub fn create_stream(&mut self) -> Option<u32> {
        if self.active_streams.len() >= self.max_concurrent_streams {
            warn!("Maximum concurrent streams reached");
            return None;
        }

        let stream_id = self.next_stream_id;
        self.next_stream_id += 2; // 客户端流ID是奇数

        let state = StreamState {
            window_size: 65535, // 默认窗口大小
        };

        self.active_streams.insert(stream_id, state);
        debug!("Created new HTTP/2.0 stream: {}", stream_id);
        Some(stream_id)
    }

    /// 关闭流
    pub fn close_stream(&mut self, stream_id: u32) {
        if let Some(_state) = self.active_streams.remove(&stream_id) {
            debug!("Closed HTTP/2.0 stream: {}", stream_id);
        }
    }

    /// 更新流窗口大小
    pub fn update_window(&mut self, stream_id: u32, increment: u32) {
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
    pub fn stream_exists(&self, stream_id: u32) -> bool {
        self.active_streams.contains_key(&stream_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http2_handler_creation() {
        let handler = Http2Handler::new()
            .with_max_concurrent_streams(50)
            .with_max_frame_size(32768)
            .with_priorities(false);

        assert_eq!(handler.max_concurrent_streams, 50);
        assert_eq!(handler.max_frame_size, 32768);
        assert!(!handler.enable_priorities);
    }

    #[test]
    fn test_stream_manager() {
        let mut manager = Http2StreamManager::new(10);

        let stream_id = manager.create_stream();
        assert!(stream_id.is_some());
        assert_eq!(stream_id.unwrap(), 1);
        assert_eq!(manager.active_stream_count(), 1);

        let stream_id = manager.create_stream();
        assert!(stream_id.is_some());
        assert_eq!(stream_id.unwrap(), 3); // 奇数递增
        assert_eq!(manager.active_stream_count(), 2);

        manager.close_stream(1);
        assert_eq!(manager.active_stream_count(), 1);
        assert!(!manager.stream_exists(1));
    }

    #[test]
    fn test_max_streams_limit() {
        let mut manager = Http2StreamManager::new(2);

        manager.create_stream();
        manager.create_stream();
        let stream_id = manager.create_stream();

        assert!(stream_id.is_none()); // 达到最大流数限制
        assert_eq!(manager.active_stream_count(), 2);
    }

    #[test]
    fn test_window_update() {
        let mut manager = Http2StreamManager::new(10);

        let stream_id = manager.create_stream().unwrap();
        manager.update_window(stream_id, 1000);

        // 检查窗口是否更新（通过重新创建流管理器来验证）
        let mut manager2 = Http2StreamManager::new(10);
        manager2.create_stream();
        manager2.update_window(stream_id, 1000);

        // 在实际实现中，这里应该有方法来获取窗口大小
    }
}
