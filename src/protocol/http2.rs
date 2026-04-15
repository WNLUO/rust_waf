use super::{HttpVersion, ProtocolError, UnifiedHttpRequest};
use bytes::{Buf, Bytes};
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::{Body, Incoming};
use hyper::server::conn::http2;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use log::{debug, warn};
use std::collections::HashMap;
use std::future::Future;
use tokio::io::{AsyncRead, AsyncWrite};

pub type Http2ResponseBody = Full<Bytes>;

fn is_disallowed_http2_response_header(header_name: &str) -> bool {
    header_name.eq_ignore_ascii_case("transfer-encoding")
        || header_name.eq_ignore_ascii_case("connection")
        || header_name.eq_ignore_ascii_case("keep-alive")
        || header_name.eq_ignore_ascii_case("proxy-connection")
        || header_name.eq_ignore_ascii_case("upgrade")
        || header_name.eq_ignore_ascii_case("te")
        || header_name.starts_with(':')
}

#[derive(Debug, Clone)]
pub struct Http2Response {
    pub status_code: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// HTTP/2.0处理器
///
/// 基于 hyper 的 HTTP/2 server connection，把真实的 h2 请求转换为统一请求结构。
pub struct Http2Handler {
    max_concurrent_streams: usize,
    max_frame_size: usize,
    enable_priorities: bool,
    initial_window_size: u32,
}

impl Http2Handler {
    /// 创建新的HTTP/2.0处理器
    pub fn new() -> Self {
        Self {
            max_concurrent_streams: 100,
            max_frame_size: 16_384,
            enable_priorities: true,
            initial_window_size: 65_535,
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

    /// 设置初始窗口大小
    pub fn with_initial_window_size(mut self, size: u32) -> Self {
        self.initial_window_size = size;
        self
    }

    /// 驱动一个 HTTP/2 连接，并把每个请求转换成 UnifiedHttpRequest 交给回调处理。
    pub async fn serve_connection<H, Fut, E, Eut>(
        &self,
        stream: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
        client_ip: String,
        listener_port: u16,
        max_size: usize,
        read_idle_timeout_ms: u64,
        body_min_bytes_per_sec: u32,
        handler: H,
        error_handler: E,
    ) -> Result<(), ProtocolError>
    where
        H: Fn(UnifiedHttpRequest) -> Fut + Clone + Send + 'static,
        Fut: Future<Output = Result<Http2Response, ProtocolError>> + Send + 'static,
        E: Fn(ProtocolError) -> Eut + Clone + Send + 'static,
        Eut: Future<Output = Result<Http2Response, ProtocolError>> + Send + 'static,
    {
        let io = TokioIo::new(stream);
        let mut builder = http2::Builder::new(TokioExecutor::new());
        builder.max_concurrent_streams(Some(self.max_concurrent_streams as u32));
        builder.max_frame_size(Some(self.max_frame_size as u32));
        builder.initial_stream_window_size(Some(self.initial_window_size));
        builder.initial_connection_window_size(Some(
            self.initial_window_size
                .saturating_mul(self.max_concurrent_streams.min(16) as u32),
        ));

        if !self.enable_priorities {
            debug!("HTTP/2 priority hints are disabled in config");
        }

        let service = service_fn(move |request: Request<Incoming>| {
            let handler = handler.clone();
            let error_handler = error_handler.clone();
            let client_ip = client_ip.clone();
            async move {
                let is_head_request = request.method() == http::Method::HEAD;
                let response = match Http2Handler::request_to_unified(
                    request,
                    &client_ip,
                    listener_port,
                    max_size,
                    read_idle_timeout_ms,
                    body_min_bytes_per_sec,
                )
                .await
                {
                    Ok(unified) => handler(unified).await?,
                    Err(err) => error_handler(err).await?,
                };
                Ok::<_, ProtocolError>(Http2Handler::build_response(response, is_head_request))
            }
        });

        builder
            .serve_connection(io, service)
            .await
            .map_err(|err| ProtocolError::ParseError(format!("HTTP/2 connection error: {:?}", err)))
    }

    async fn request_to_unified<B>(
        request: Request<B>,
        client_ip: &str,
        listener_port: u16,
        max_size: usize,
        read_idle_timeout_ms: u64,
        body_min_bytes_per_sec: u32,
    ) -> Result<UnifiedHttpRequest, ProtocolError>
    where
        B: Body + Send + Unpin + 'static,
        B::Data: Buf,
        B::Error: std::fmt::Display,
    {
        let (parts, body) = request.into_parts();
        let body =
            read_http2_request_body(body, max_size, read_idle_timeout_ms, body_min_bytes_per_sec)
                .await?;

        if body.len() > max_size {
            return Err(ProtocolError::ParseError(format!(
                "HTTP/2 request body exceeded limit: {} > {}",
                body.len(),
                max_size
            )));
        }

        let method = parts.method.as_str().to_string();
        let uri = parts
            .uri
            .path_and_query()
            .map(|pq| pq.as_str().to_string())
            .unwrap_or_else(|| parts.uri.path().to_string());

        let mut unified = UnifiedHttpRequest::new(HttpVersion::Http2_0, method, uri);
        unified.body = body.to_vec();
        unified.set_client_ip(client_ip.to_string());
        unified.add_metadata("listener_port".to_string(), listener_port.to_string());
        unified.add_metadata("protocol".to_string(), "HTTP/2.0".to_string());

        if let Some(scheme) = parts.uri.scheme_str() {
            unified.add_metadata("scheme".to_string(), scheme.to_string());
        }

        let authority = parts
            .uri
            .authority()
            .map(|authority| authority.as_str().to_string())
            .or_else(|| {
                parts
                    .headers
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

        for (key, value) in &parts.headers {
            let value = value.to_str().map_err(|err| {
                ProtocolError::ParseError(format!("Invalid HTTP/2 header '{}': {}", key, err))
            })?;
            unified.add_header(key.as_str().to_string(), value.to_string());
        }

        if let Some(trailers) = extract_trailer_metadata(&parts.extensions) {
            for (key, value) in trailers {
                unified.add_metadata(format!("trailer.{}", key), value);
            }
        }

        Ok(unified)
    }

    fn build_response(
        response: Http2Response,
        is_head_request: bool,
    ) -> Response<Http2ResponseBody> {
        let status =
            StatusCode::from_u16(response.status_code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let body_len = response.body.len();
        let body = if is_head_request {
            Bytes::new()
        } else {
            Bytes::from(response.body)
        };
        let mut builder = Response::builder().status(status);
        let mut has_content_type = false;
        let mut has_content_length = false;

        for (key, value) in response.headers {
            if is_disallowed_http2_response_header(&key) {
                continue;
            }
            if key.eq_ignore_ascii_case("content-type") {
                has_content_type = true;
            }
            if key.eq_ignore_ascii_case("content-length") {
                has_content_length = true;
                continue;
            }
            builder = builder.header(key, value);
        }

        if !has_content_type {
            builder = builder.header("content-type", "text/plain; charset=utf-8");
        }
        if has_content_length || body_len > 0 || status != StatusCode::NO_CONTENT {
            builder = builder.header("content-length", body_len.to_string());
        }

        builder.body(Full::new(body)).unwrap_or_else(|err| {
            warn!("Failed to build HTTP/2 response: {}", err);
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .header("content-type", "text/plain; charset=utf-8")
                .body(Full::from(Bytes::from_static(b"internal server error")))
                .expect("fallback HTTP/2 response must be valid")
        })
    }
}

async fn read_http2_request_body<B>(
    mut body: B,
    max_size: usize,
    read_idle_timeout_ms: u64,
    body_min_bytes_per_sec: u32,
) -> Result<Bytes, ProtocolError>
where
    B: Body + Send + Unpin + 'static,
    B::Data: Buf,
    B::Error: std::fmt::Display,
{
    let mut collected = Vec::new();
    let started_at = std::time::Instant::now();

    while let Some(frame) = tokio::time::timeout(
        std::time::Duration::from_millis(read_idle_timeout_ms),
        body.frame(),
    )
    .await
    .map_err(|_| ProtocolError::SlowBody {
        bytes_read: collected.len(),
        expected_bytes: collected.len().max(1),
        elapsed_ms: started_at.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
    })? {
        let frame = frame.map_err(|err| {
            ProtocolError::ParseError(format!("HTTP/2 body read failed: {}", err))
        })?;
        if let Ok(mut data) = frame.into_data() {
            let remaining = data.remaining();
            if collected.len() + remaining > max_size {
                return Err(ProtocolError::ParseError(format!(
                    "HTTP/2 request body exceeded limit: {} > {}",
                    collected.len() + remaining,
                    max_size
                )));
            }
            collected.extend_from_slice(data.copy_to_bytes(remaining).as_ref());
            if body_min_bytes_per_sec > 0
                && started_at.elapsed() >= std::time::Duration::from_secs(1)
                && (collected.len() as f64 / started_at.elapsed().as_secs_f64())
                    < body_min_bytes_per_sec as f64
            {
                return Err(ProtocolError::SlowBody {
                    bytes_read: collected.len(),
                    expected_bytes: collected.len().max(1),
                    elapsed_ms: started_at.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
                });
            }
        }
    }

    Ok(Bytes::from(collected))
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
    active_streams: HashMap<u32, StreamState>,
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
            active_streams: HashMap::new(),
            next_stream_id: 1,
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
        self.next_stream_id += 2;

        let state = StreamState {
            window_size: 65_535,
        };
        self.active_streams.insert(stream_id, state);
        debug!("Created new HTTP/2.0 stream: {}", stream_id);
        Some(stream_id)
    }

    /// 关闭流
    pub fn close_stream(&mut self, stream_id: u32) {
        if self.active_streams.remove(&stream_id).is_some() {
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

fn extract_trailer_metadata(extensions: &http::Extensions) -> Option<Vec<(String, String)>> {
    let trailers = extensions.get::<http::HeaderMap>()?;
    let values = trailers
        .iter()
        .filter_map(|(key, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (key.to_string(), value.to_string()))
        })
        .collect::<Vec<_>>();

    (!values.is_empty()).then_some(values)
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Request;

    #[test]
    fn test_http2_handler_creation() {
        let handler = Http2Handler::new()
            .with_max_concurrent_streams(50)
            .with_max_frame_size(32_768)
            .with_priorities(false)
            .with_initial_window_size(131_072);

        assert_eq!(handler.max_concurrent_streams, 50);
        assert_eq!(handler.max_frame_size, 32_768);
        assert!(!handler.enable_priorities);
        assert_eq!(handler.initial_window_size, 131_072);
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
        assert_eq!(stream_id.unwrap(), 3);
        assert_eq!(manager.active_stream_count(), 2);

        manager.close_stream(1);
        assert_eq!(manager.active_stream_count(), 1);
        assert!(!manager.stream_exists(1));
    }

    #[tokio::test]
    async fn test_request_to_unified_preserves_http2_metadata() {
        let request: Request<Full<Bytes>> = Request::builder()
            .method("POST")
            .uri("https://example.com/api?q=1")
            .header("content-type", "application/json")
            .header("x-test", "demo")
            .body(Full::new(Bytes::from_static(br#"{"ok":true}"#)))
            .unwrap();

        let unified = Http2Handler::request_to_unified(request, "127.0.0.1", 8443, 1024, 5_000, 16)
            .await
            .unwrap();

        assert_eq!(unified.version, HttpVersion::Http2_0);
        assert_eq!(unified.method, "POST");
        assert_eq!(unified.uri, "/api?q=1");
        assert_eq!(
            unified.get_metadata("authority"),
            Some(&"example.com".to_string())
        );
        assert_eq!(unified.get_header("host"), Some(&"example.com".to_string()));
        assert_eq!(unified.get_metadata("scheme"), Some(&"https".to_string()));
        assert_eq!(unified.body, br#"{"ok":true}"#.to_vec());
    }

    #[test]
    fn test_build_response_filters_hop_by_hop_headers() {
        let response = Http2Handler::build_response(
            Http2Response {
                status_code: 200,
                headers: vec![
                    ("transfer-encoding".to_string(), "chunked".to_string()),
                    ("connection".to_string(), "keep-alive".to_string()),
                    ("keep-alive".to_string(), "timeout=5".to_string()),
                    ("content-type".to_string(), "text/plain".to_string()),
                ],
                body: b"ok".to_vec(),
            },
            false,
        );

        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().get("transfer-encoding").is_none());
        assert!(response.headers().get("connection").is_none());
        assert!(response.headers().get("keep-alive").is_none());
        assert_eq!(response.headers()["content-type"], "text/plain");
    }

    #[test]
    fn test_build_response_rewrites_duplicate_content_length() {
        let response = Http2Handler::build_response(
            Http2Response {
                status_code: 200,
                headers: vec![
                    ("content-length".to_string(), "999".to_string()),
                    ("content-type".to_string(), "text/plain".to_string()),
                ],
                body: b"ok".to_vec(),
            },
            false,
        );

        let values = response.headers().get_all("content-length");
        assert_eq!(values.iter().count(), 1);
        assert_eq!(response.headers()["content-length"], "2");
    }

    #[test]
    fn test_head_response_keeps_content_length() {
        let response = Http2Handler::build_response(
            Http2Response {
                status_code: 404,
                headers: vec![("content-type".to_string(), "text/plain".to_string())],
                body: b"site not found".to_vec(),
            },
            true,
        );

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(response.headers()["content-length"], "14");
    }
}
